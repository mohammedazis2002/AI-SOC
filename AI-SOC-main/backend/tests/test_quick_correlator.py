"""
Test Quick Correlator (Path B)
================================
Uses fakeredis to mock Redis.
Covers: same-user burst, same-IP burst, MITRE fast patterns,
        Redis key injection, isolated alerts, and Redis-offline fallback.
"""

import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))


# ---------------------------------------------------------------------------
# Fake Redis that behaves like redis.asyncio.Redis
# ---------------------------------------------------------------------------

class FakeRedis:
    """Minimal async Redis mock for list / pipeline operations."""

    def __init__(self):
        self._data = {}

    class Pipeline:
        def __init__(self, store):
            self._store = store
            self._ops = []

        def lpush(self, key, value):
            self._ops.append(("lpush", key, value))
            return self

        def ltrim(self, key, start, stop):
            self._ops.append(("ltrim", key, start, stop))
            return self

        def expire(self, key, ttl):
            self._ops.append(("expire", key, ttl))
            return self

        async def execute(self):
            for op in self._ops:
                if op[0] == "lpush":
                    key, val = op[1], op[2]
                    if key not in self._store:
                        self._store[key] = []
                    self._store[key].insert(0, val)
                elif op[0] == "ltrim":
                    key, start, stop = op[1], op[2], op[3]
                    if key in self._store:
                        self._store[key] = self._store[key][start:stop + 1]
            self._ops.clear()

    def pipeline(self):
        return self.Pipeline(self._data)

    async def lrange(self, key, start, stop):
        lst = self._data.get(key, [])
        return lst[start:stop + 1]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(
    alert_id: str,
    user: str = "john.doe",
    source_ip: str = "10.0.0.1",
    mitre_technique: str = "",
    severity: str = "medium",
) -> dict:
    return {
        "alert_id": alert_id,
        "user": user,
        "source_ip": source_ip,
        "mitre_technique": mitre_technique,
        "severity": severity,
        "time": int(datetime.now().timestamp() * 1000),
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_redis():
    return FakeRedis()


@pytest.fixture
def quick_engine(fake_redis):
    from services.correlation.quick_correlator import QuickCorrelationEngine
    return QuickCorrelationEngine(redis_client=fake_redis)


class TestSameUserBurst:
    """≥2 alerts from the same user in 5 min → same_user_burst."""

    def test_two_alerts_triggers_burst(self, quick_engine, fake_redis):
        a1 = _make_alert("a1", user="jane.smith")
        a2 = _make_alert("a2", user="jane.smith")

        # Feed first alert (no correlations yet — only 1 in cache at query time)
        r1 = asyncio.get_event_loop().run_until_complete(
            quick_engine.quick_correlate(a1)
        )
        assert len(r1) == 0  # First alert, nothing to correlate with

        # Feed second alert → should find same_user_burst
        r2 = asyncio.get_event_loop().run_until_complete(
            quick_engine.quick_correlate(a2)
        )
        burst_types = [r.correlation_type.value for r in r2]
        assert "same_user_burst" in burst_types

    def test_different_users_no_burst(self, quick_engine):
        a1 = _make_alert("a1", user="alice")
        a2 = _make_alert("a2", user="bob")

        asyncio.get_event_loop().run_until_complete(quick_engine.quick_correlate(a1))
        r2 = asyncio.get_event_loop().run_until_complete(
            quick_engine.quick_correlate(a2)
        )
        burst_types = [r.correlation_type.value for r in r2]
        assert "same_user_burst" not in burst_types


class TestSameIPBurst:
    """≥2 alerts from the same IP in 5 min → same_ip_burst."""

    def test_same_ip(self, quick_engine):
        a1 = _make_alert("a1", user="u1", source_ip="192.168.1.10")
        a2 = _make_alert("a2", user="u2", source_ip="192.168.1.10")

        asyncio.get_event_loop().run_until_complete(quick_engine.quick_correlate(a1))
        r2 = asyncio.get_event_loop().run_until_complete(
            quick_engine.quick_correlate(a2)
        )
        burst_types = [r.correlation_type.value for r in r2]
        assert "same_ip_burst" in burst_types


class TestFastMITREPatterns:
    """Phishing (T1566.*) → Credential theft (T1056.001) within 15 min."""

    def test_phishing_then_credential_theft(self, quick_engine):
        a1 = _make_alert("a1", mitre_technique="T1566.001")
        a2 = _make_alert("a2", mitre_technique="T1056.001")

        asyncio.get_event_loop().run_until_complete(quick_engine.quick_correlate(a1))
        r2 = asyncio.get_event_loop().run_until_complete(
            quick_engine.quick_correlate(a2)
        )
        types = [r.correlation_type.value for r in r2]
        assert "phishing_to_credential_theft" in types

    def test_powershell_then_encryption(self, quick_engine):
        a1 = _make_alert("a1", mitre_technique="T1059.001")
        a2 = _make_alert("a2", mitre_technique="T1486")

        asyncio.get_event_loop().run_until_complete(quick_engine.quick_correlate(a1))
        r2 = asyncio.get_event_loop().run_until_complete(
            quick_engine.quick_correlate(a2)
        )
        types = [r.correlation_type.value for r in r2]
        assert "powershell_to_encryption" in types


class TestRedisKeyInjection:
    """Malicious user values should be SHA-256 hashed, not injected into keys."""

    def test_malicious_user_is_hashed(self, quick_engine, fake_redis):
        # User value that contains special characters
        a = _make_alert("a1", user="evil\x00;FLUSHALL")
        asyncio.get_event_loop().run_until_complete(quick_engine.quick_correlate(a))

        # Redis keys should NOT contain the raw input
        for key in fake_redis._data:
            assert "FLUSHALL" not in key
            assert "\x00" not in key


class TestIsolatedAlert:
    """Single alert, no history → empty result."""

    def test_no_correlation(self, quick_engine):
        a = _make_alert("lone-wolf", user="unique-user-xyz-999")
        r = asyncio.get_event_loop().run_until_complete(
            quick_engine.quick_correlate(a)
        )
        assert r == []


class TestRedisOffline:
    """If Redis is unavailable, return empty list (never raise)."""

    def test_redis_none_returns_empty(self):
        from services.correlation.quick_correlator import QuickCorrelationEngine
        engine = QuickCorrelationEngine(redis_client=None)
        a = _make_alert("a1")
        r = asyncio.get_event_loop().run_until_complete(engine.quick_correlate(a))
        assert r == []
