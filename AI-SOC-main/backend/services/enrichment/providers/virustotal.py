"""
VirusTotal Provider
===================
Lookups: IP reputation, domain, file hash (MD5/SHA256/SHA1)
API: https://www.virustotal.com/api/v3/
Rate limit: 500 req/day (free), 4 req/min
Cache TTL: 24h
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional

import aiohttp

from ..ti_cache import get_ti_cache

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]


class VirusTotalProvider:
    """VirusTotal threat intelligence provider."""

    def __init__(self):
        self.cache = get_ti_cache()
        self.provider = "virustotal"

    def _get_api_key(self) -> Optional[str]:
        return self.cache.get_api_key(self.provider, "VIRUSTOTAL_API_KEY")

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up IP reputation."""
        cached = self.cache.get(self.provider, f"ip:{ip}")
        if cached is not None:
            return cached

        result = await self._request(f"/ip_addresses/{ip}")
        parsed = self._parse_ip(result)
        self.cache.set(self.provider, f"ip:{ip}", parsed)
        return parsed

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up file hash (MD5/SHA1/SHA256)."""
        cached = self.cache.get(self.provider, f"hash:{file_hash}")
        if cached is not None:
            return cached

        result = await self._request(f"/files/{file_hash}")
        parsed = self._parse_file(result)
        self.cache.set(self.provider, f"hash:{file_hash}", parsed)
        return parsed

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up domain reputation."""
        cached = self.cache.get(self.provider, f"domain:{domain}")
        if cached is not None:
            return cached

        result = await self._request(f"/domains/{domain}")
        parsed = self._parse_domain(result)
        self.cache.set(self.provider, f"domain:{domain}", parsed)
        return parsed

    async def _request(self, path: str) -> Optional[Dict]:
        """Make authenticated request with retry + exponential backoff."""
        api_key = self._get_api_key()
        if not api_key:
            logger.warning("VirusTotal: no API key configured")
            return None

        headers = {"x-apikey": api_key}
        url = f"{VT_BASE}{path}"

        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        elif resp.status == 404:
                            return None  # Not found — don't retry
                        elif resp.status in (401, 403):
                            logger.error(f"VirusTotal: auth error {resp.status}")
                            return None
                        elif resp.status == 429:
                            logger.warning(f"VirusTotal: rate limited, retry {attempt+1}/{MAX_RETRIES}")
                        else:
                            logger.warning(f"VirusTotal: HTTP {resp.status}, retry {attempt+1}/{MAX_RETRIES}")
            except asyncio.TimeoutError:
                logger.warning(f"VirusTotal: timeout, retry {attempt+1}/{MAX_RETRIES}")
            except Exception as e:
                logger.warning(f"VirusTotal: error {e}, retry {attempt+1}/{MAX_RETRIES}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)

        return None

    def _parse_ip(self, data: Optional[Dict]) -> Dict[str, Any]:
        if not data:
            return {"available": False}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(stats.values()),
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country", ""),
            "asn": attrs.get("asn", ""),
            "as_owner": attrs.get("as_owner", ""),
            "network": attrs.get("network", ""),
            "is_malicious": stats.get("malicious", 0) >= 3,
        }

    def _parse_file(self, data: Optional[Dict]) -> Dict[str, Any]:
        if not data:
            return {"available": False}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values()),
            "name": attrs.get("meaningful_name", ""),
            "type": attrs.get("type_description", ""),
            "size": attrs.get("size", 0),
            "tags": attrs.get("tags", []),
            "is_malicious": stats.get("malicious", 0) >= 3,
        }

    def _parse_domain(self, data: Optional[Dict]) -> Dict[str, Any]:
        if not data:
            return {"available": False}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values()),
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
            "is_malicious": stats.get("malicious", 0) >= 3,
        }
