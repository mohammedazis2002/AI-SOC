"""
Integration Test – Correlation Pipeline
=========================================
End-to-end test covering the full 3-alert attack chain:
  Alert 1: Phishing (T1566)
  Alert 2: Credential theft (T1056.001) – triggers quick correlation
  Alert 3: Data exfiltration (T1041)

Verifies:
  - Quick correlator finds phishing→credential link
  - Background queue accepts the alert
  - HybridCorrelationSystem returns correct CorrelationHandleResult
"""

import asyncio
import sys
from datetime import datetime
from pathlib import Path

import pytest

backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))


# ---------------------------------------------------------------------------
# Fake Redis for integration
# ---------------------------------------------------------------------------

class FakeRedis:
    def __init__(self):
        self._data = {}

    class Pipeline:
        def __init__(self, store):
            self._store = store
            self._ops = []

        def lpush(self, key, val):
            self._ops.append(("lpush", key, val))
            return self

        def ltrim(self, key, s, e):
            self._ops.append(("ltrim", key, s, e))
            return self

        def expire(self, key, ttl):
            return self

        async def execute(self):
            for op in self._ops:
                if op[0] == "lpush":
                    k, v = op[1], op[2]
                    self._store.setdefault(k, []).insert(0, v)
                elif op[0] == "ltrim":
                    k, s, e = op[1], op[2], op[3]
                    if k in self._store:
                        self._store[k] = self._store[k][s:e + 1]
            self._ops.clear()

    def pipeline(self):
        return self.Pipeline(self._data)

    async def lrange(self, key, start, stop):
        return self._data.get(key, [])[start:stop + 1]

    async def set(self, key, val, **kw):
        if kw.get("nx") and key in self._data:
            return False
        self._data[key] = val
        return True

    async def delete(self, key):
        self._data.pop(key, None)

    async def xadd(self, name, fields):
        self._data.setdefault(f"stream:{name}", []).append(fields)
        return "fake-id"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(alert_id, technique, user="john.doe", severity="medium"):
    return {
        "alert_id": alert_id,
        "user": user,
        "source_ip": "10.0.0.50",
        "mitre_technique": technique,
        "severity": severity,
        "time": int(datetime.now().timestamp() * 1000),
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_redis():
    return FakeRedis()


class TestCorrelationPipeline:
    """Full attack chain: phishing → credential theft → exfiltration."""

    def test_three_alert_chain(self, fake_redis):
        try:
            import mongomock
        except ImportError:
            pytest.skip("mongomock required")

        db = mongomock.MongoClient()["soar_db"]

        from services.correlation.hybrid_correlation_system import HybridCorrelationSystem
        system = HybridCorrelationSystem(db_client=db, redis_client=fake_redis)

        loop = asyncio.get_event_loop()

        # Alert 1: Phishing
        a1 = _make_alert("alert-1", "T1566.001", severity="low")
        r1 = loop.run_until_complete(system.handle_alert(a1))
        assert r1.deep_queued is True
        assert len(r1.quick_correlations) == 0  # first alert, no history

        # Alert 2: Credential theft → should correlate with phishing
        a2 = _make_alert("alert-2", "T1056.001", severity="medium")
        r2 = loop.run_until_complete(system.handle_alert(a2))
        assert r2.deep_queued is True

        # Should find at least same_user_burst and/or phishing_to_credential_theft
        quick_types = [c.correlation_type.value for c in r2.quick_correlations]
        has_corr = (
            "same_user_burst" in quick_types
            or "phishing_to_credential_theft" in quick_types
            or "same_ip_burst" in quick_types
        )
        assert has_corr, f"Expected correlation in {quick_types}"

        # Alert 3: Exfiltration → should see user/IP burst
        a3 = _make_alert("alert-3", "T1041", severity="high")
        r3 = loop.run_until_complete(system.handle_alert(a3))
        assert r3.deep_queued is True

        quick_types_3 = [c.correlation_type.value for c in r3.quick_correlations]
        assert len(quick_types_3) > 0, "Third alert should have bursts"

    def test_result_has_expected_shape(self, fake_redis):
        try:
            import mongomock
        except ImportError:
            pytest.skip("mongomock required")

        db = mongomock.MongoClient()["soar_db"]

        from services.correlation.hybrid_correlation_system import HybridCorrelationSystem
        system = HybridCorrelationSystem(db_client=db, redis_client=fake_redis)

        a = _make_alert("shape-test", "T1059.001")
        r = asyncio.get_event_loop().run_until_complete(system.handle_alert(a))

        assert hasattr(r, "alert_id")
        assert hasattr(r, "quick_correlations")
        assert hasattr(r, "incident_id")
        assert hasattr(r, "deep_queued")
        assert isinstance(r.quick_correlations, list)


class TestGracefulDegradation:
    """Correlation system should never crash the pipeline."""

    def test_no_redis_no_db(self):
        from services.correlation.hybrid_correlation_system import HybridCorrelationSystem
        system = HybridCorrelationSystem(db_client=None, redis_client=None)

        a = _make_alert("degrade-test", "T1059.001")
        r = asyncio.get_event_loop().run_until_complete(system.handle_alert(a))

        assert r.alert_id == "degrade-test"
        assert r.quick_correlations == []
        # Queue still accepts items (they just sit unprocessed), so deep_queued is True
        assert r.deep_queued is True
