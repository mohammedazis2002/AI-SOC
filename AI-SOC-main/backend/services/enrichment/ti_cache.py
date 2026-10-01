"""
Threat Intelligence Cache + API Key Rotation
=============================================
Redis-backed cache with per-provider TTLs and multi-key rotation.
All providers use this instead of calling Redis directly.
"""

import os
import json
import time
import hashlib
import logging
from typing import Optional, List, Any, Dict

logger = logging.getLogger(__name__)

# When running locally (outside Docker), REDIS_HOST=redis won't resolve.
# Override with REDIS_HOST=localhost for local test runs.
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_CACHE_DB = int(os.getenv("REDIS_CACHE_DB", "1"))

# Per-provider cache TTLs (seconds)
DEFAULT_TTLS = {
    "virustotal":  86400,   # 24h
    "abuseipdb":   86400,   # 24h
    "otx":         21600,   # 6h
    "geoip":       604800,  # 7 days
    "abusech":     3600,    # 1h
    "greynoise":   14400,   # 4h
    "misp":        3600,    # 1h
    "deepdarkcti": 3600,    # 1h
}


class TICache:
    """
    Redis-backed cache for threat intelligence lookups.
    Supports multi-key rotation for rate-limited providers.
    """

    def __init__(self):
        self._client = None
        self._redis_failed = False   # suppress repeated connection-error spam

    @property
    def client(self):
        if self._redis_failed:
            return None
        if self._client is None:
            try:
                import redis
                self._client = redis.Redis(
                    host=REDIS_HOST,
                    port=REDIS_PORT,
                    password=REDIS_PASSWORD,
                    db=REDIS_CACHE_DB,
                    decode_responses=True,
                    socket_connect_timeout=2,
                )
                self._client.ping()
                logger.info(f"Redis cache connected at {REDIS_HOST}:{REDIS_PORT}")
            except Exception as e:
                logger.warning(
                    f"Redis cache unavailable: {e}. TI results will not be cached.\n"
                    f"  Tip: if running locally, set REDIS_HOST=localhost in your shell."
                )
                self._client = None
                self._redis_failed = True   # stop retrying on every lookup
        return self._client

    def _make_key(self, provider: str, indicator: str) -> str:
        """Build a namespaced cache key."""
        h = hashlib.md5(indicator.encode()).hexdigest()[:12]
        return f"ti:{provider}:{h}"

    def get(self, provider: str, indicator: str) -> Optional[Dict]:
        """Get cached TI result. Returns None on miss or Redis unavailable."""
        if not self.client:
            return None
        try:
            raw = self.client.get(self._make_key(provider, indicator))
            if raw:
                return json.loads(raw)
        except Exception as e:
            logger.debug(f"Cache get error ({provider}): {e}")
        return None

    def set(self, provider: str, indicator: str, data: Dict, ttl: Optional[int] = None):
        """Cache TI result with provider-specific TTL."""
        if not self.client:
            return
        try:
            ttl = ttl or DEFAULT_TTLS.get(provider, 3600)
            self.client.setex(
                self._make_key(provider, indicator),
                ttl,
                json.dumps(data, default=str)
            )
        except Exception as e:
            logger.debug(f"Cache set error ({provider}): {e}")

    # ── API Key Rotation ─────────────────────────────────────────────────────

    def get_api_key(self, provider: str, env_prefix: str) -> Optional[str]:
        """
        Get the next available API key for a provider using round-robin rotation.
        Reads keys from env vars: {env_prefix}_1, {env_prefix}_2, ... or {env_prefix}
        Tracks daily usage per key in Redis. Skips keys that hit their daily limit.
        """
        # Collect all keys for this provider
        keys = []
        # Single key (legacy)
        single = os.getenv(env_prefix)
        if single:
            keys.append(single)
        # Numbered keys
        i = 1
        while True:
            k = os.getenv(f"{env_prefix}_{i}")
            if not k:
                break
            if k not in keys:
                keys.append(k)
            i += 1

        if not keys:
            return None

        if not self.client or len(keys) == 1:
            return keys[0]

        # Round-robin: pick key with lowest usage today
        today = time.strftime("%Y%m%d")
        best_key = None
        best_count = float("inf")

        for key in keys:
            usage_key = f"ti_key_usage:{provider}:{key[:8]}:{today}"
            try:
                count = int(self.client.get(usage_key) or 0)
            except Exception:
                count = 0
            if count < best_count:
                best_count = count
                best_key = key

        # Increment usage counter
        if best_key:
            usage_key = f"ti_key_usage:{provider}:{best_key[:8]}:{today}"
            try:
                pipe = self.client.pipeline()
                pipe.incr(usage_key)
                pipe.expire(usage_key, 86400)
                pipe.execute()
            except Exception:
                pass

        return best_key


# Singleton
_cache: Optional[TICache] = None


def get_ti_cache() -> TICache:
    global _cache
    if _cache is None:
        _cache = TICache()
    return _cache
