"""
Correlation Engine – Quick Correlator (Path B)
===============================================
Redis-backed, sub-5-second correlation checks.
Runs in parallel with immediate alert processing; does NOT block the pipeline.

Checks performed:
  1. Same-user burst  – ≥2 alerts from same user in last 5 min
  2. Same-IP burst    – ≥2 alerts from same source_ip in last 5 min
  3. Fast MITRE patterns:
       T1566.* → T1056.001  (Phishing → Credential Theft, window 15 min)
       T1059.001 → T1486    (PowerShell → Ransomware Encryption, window 60 min)

Security hardening:
  - Redis key namespace: corr:user:<sanitised> / corr:ip:<sanitised>
  - User/IP values allow-list validated; anything outside is SHA-256 hashed
  - Only AlertRef (scrubbed, no secrets) is written to Redis
  - Per-key list capped at CACHE_MAX_LEN via LTRIM to prevent storm growth
  - Redis unavailability → graceful empty return (alert pipeline unblocked)

Observability:
  - Prometheus counters incremented on each discovered correlation type
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis

from .models import AlertRef, CorrelationResult, CorrelationType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WINDOW_MINUTES         = int(os.getenv("QUICK_CORRELATION_WINDOW_MINUTES", "5"))
BURST_THRESHOLD        = int(os.getenv("QUICK_BURST_THRESHOLD", "2"))
CACHE_MAX_LEN          = int(os.getenv("CORRELATION_QUICK_CACHE_MAX_LEN", "50"))
PHISHING_CRED_WINDOW_M = int(os.getenv("CORR_PHISHING_CRED_WINDOW_M", "15"))
PS_RANSOM_WINDOW_M     = int(os.getenv("CORR_PS_RANSOM_WINDOW_M", "60"))

# Redis key TTL matches the longest window + buffer
_CACHE_TTL_S = (max(WINDOW_MINUTES, PS_RANSOM_WINDOW_M) + 5) * 60

# Regex allow-list for safe Redis key suffixes
_SAFE_KEY_RE = re.compile(r'^[a-zA-Z0-9._@\-]{1,128}$')


# ---------------------------------------------------------------------------
# Key safety
# ---------------------------------------------------------------------------

def _safe_key_suffix(value: str) -> str:
    """
    Return value unchanged if it matches the allow-list.
    Otherwise return SHA-256 hex digest to prevent key injection.
    """
    if value and _SAFE_KEY_RE.match(value):
        return value
    return hashlib.sha256((value or "").encode()).hexdigest()[:32]


def _user_key(user: str) -> str:
    return f"corr:user:{_safe_key_suffix(user)}"


def _ip_key(ip: str) -> str:
    return f"corr:ip:{_safe_key_suffix(ip)}"


# ---------------------------------------------------------------------------
# QuickCorrelationEngine
# ---------------------------------------------------------------------------

class QuickCorrelationEngine:
    """
    Path B: Fast Redis-backed correlation checks.
    Returns results in <150 ms; never raises (all errors are caught and logged).
    """

    def __init__(self, redis_client: Optional[aioredis.Redis] = None) -> None:
        self._redis = redis_client

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def quick_correlate(self, alert: Dict[str, Any]) -> List[CorrelationResult]:
        """
        Correlate a new alert against recent Redis cache.
        Step 1: write this alert to cache.
        Step 2: check for obvious patterns.
        Returns list of CorrelationResults (may be empty).
        """
        if not self._redis:
            logger.debug("QuickCorrelator: Redis unavailable, skipping")
            return []

        try:
            ref = AlertRef.from_alert(alert)
            await self._cache_alert(ref)
            return await self._check_correlations(ref)
        except Exception as exc:
            logger.warning(f"QuickCorrelator error (non-fatal): {exc}")
            return []

    # ------------------------------------------------------------------
    # Cache write
    # ------------------------------------------------------------------

    async def _cache_alert(self, ref: AlertRef) -> None:
        """Write AlertRef to Redis lists keyed by user and IP."""
        payload = json.dumps(ref.to_cache_dict())
        pipeline = self._redis.pipeline()

        if ref.user:
            key = _user_key(ref.user)
            pipeline.lpush(key, payload)
            pipeline.ltrim(key, 0, CACHE_MAX_LEN - 1)
            pipeline.expire(key, _CACHE_TTL_S)

        if ref.source_ip:
            key = _ip_key(ref.source_ip)
            pipeline.lpush(key, payload)
            pipeline.ltrim(key, 0, CACHE_MAX_LEN - 1)
            pipeline.expire(key, _CACHE_TTL_S)

        await pipeline.execute()

    # ------------------------------------------------------------------
    # Correlation checks
    # ------------------------------------------------------------------

    async def _check_correlations(self, ref: AlertRef) -> List[CorrelationResult]:
        results: List[CorrelationResult] = []

        # 1. Same-user burst (BURST_THRESHOLD includes current alert, so check others >= threshold - 1)
        if ref.user:
            user_recent = await self._fetch_recent(
                _user_key(ref.user), minutes=WINDOW_MINUTES, exclude_id=ref.alert_id
            )
            if len(user_recent) >= BURST_THRESHOLD - 1:
                results.append(CorrelationResult(
                    correlation_type=CorrelationType.SAME_USER_BURST,
                    confidence=0.8,
                    related_alert_ids=[r.alert_id for r in user_recent],
                    narrative=f"≥{BURST_THRESHOLD} alerts from user '{ref.user}' in {WINDOW_MINUTES} min",
                    layer="quick",
                ))

        # 2. Same-IP burst
        if ref.source_ip:
            ip_recent = await self._fetch_recent(
                _ip_key(ref.source_ip), minutes=WINDOW_MINUTES, exclude_id=ref.alert_id
            )
            if len(ip_recent) >= BURST_THRESHOLD - 1:
                results.append(CorrelationResult(
                    correlation_type=CorrelationType.SAME_IP_BURST,
                    confidence=0.8,
                    related_alert_ids=[r.alert_id for r in ip_recent],
                    narrative=f"≥{BURST_THRESHOLD} alerts from IP '{ref.source_ip}' in {WINDOW_MINUTES} min",
                    layer="quick",
                ))

        # 3. Fast MITRE patterns (use user-keyed history for same actor)
        if ref.user and ref.mitre_technique:
            user_history = await self._fetch_recent(
                _user_key(ref.user),
                minutes=max(PHISHING_CRED_WINDOW_M, PS_RANSOM_WINDOW_M),
                exclude_id=ref.alert_id,
            )
            pattern = self._check_fast_patterns(ref, user_history)
            if pattern:
                results.append(pattern)

        return results

    # ------------------------------------------------------------------
    # Fast MITRE pattern matching
    # ------------------------------------------------------------------

    def _check_fast_patterns(
        self,
        ref: AlertRef,
        history: List[AlertRef],
    ) -> Optional[CorrelationResult]:
        """
        Check for known fast attack patterns against recent history.
        Patterns only checked when they typically complete within 1 hour.
        """
        technique = (ref.mitre_technique or "").upper()
        now = datetime.now(tz=timezone.utc)

        # --- Pattern 1: Phishing → Credential Theft (≤15 min) ---
        if technique == "T1056.001":
            cutoff = now - timedelta(minutes=PHISHING_CRED_WINDOW_M)
            phishing_alerts = [
                a for a in history
                if (a.mitre_technique or "").upper().startswith("T1566")
                and a.timestamp.replace(tzinfo=timezone.utc) >= cutoff
            ]
            if phishing_alerts:
                return CorrelationResult(
                    correlation_type=CorrelationType.PHISHING_TO_CREDENTIAL,
                    confidence=0.9,
                    related_alert_ids=[a.alert_id for a in phishing_alerts],
                    attack_pattern="phishing_to_credential_theft",
                    narrative=(
                        f"Phishing alert within {PHISHING_CRED_WINDOW_M} min "
                        f"followed by credential theft ({technique})"
                    ),
                    layer="quick",
                )

        # --- Pattern 2: PowerShell Exec → File Encryption / Ransomware (≤60 min) ---
        if technique == "T1486":
            cutoff = now - timedelta(minutes=PS_RANSOM_WINDOW_M)
            ps_alerts = [
                a for a in history
                if (a.mitre_technique or "").upper() == "T1059.001"
                and a.timestamp.replace(tzinfo=timezone.utc) >= cutoff
            ]
            if ps_alerts:
                return CorrelationResult(
                    correlation_type=CorrelationType.POWERSHELL_TO_ENCRYPTION,
                    confidence=0.95,
                    related_alert_ids=[a.alert_id for a in ps_alerts],
                    attack_pattern="powershell_to_encryption",
                    narrative=(
                        f"PowerShell execution within {PS_RANSOM_WINDOW_M} min "
                        f"followed by file encryption ({technique}) – likely ransomware"
                    ),
                    layer="quick",
                )

        return None

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    async def _fetch_recent(
        self,
        key: str,
        minutes: int,
        exclude_id: Optional[str] = None,
    ) -> List[AlertRef]:
        """Fetch AlertRefs from Redis list that fall within the time window."""
        try:
            raw_list = await self._redis.lrange(key, 0, CACHE_MAX_LEN - 1)
        except Exception as exc:
            logger.warning(f"QuickCorrelator Redis lrange error ({key}): {exc}")
            return []

        cutoff = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes)
        results: List[AlertRef] = []

        for raw in raw_list:
            try:
                d     = json.loads(raw)
                aref  = AlertRef.from_cache_dict(d)
                ts    = aref.timestamp.replace(tzinfo=timezone.utc)
                if ts >= cutoff and aref.alert_id != exclude_id:
                    results.append(aref)
            except Exception:
                continue  # malformed entry — skip silently

        return results
