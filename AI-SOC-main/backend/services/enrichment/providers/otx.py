"""
AlienVault OTX Provider
========================
Lookups: IP, domain, file hash via OTX pulse data
API: https://otx.alienvault.com/api/v1/
Rate limit: Unlimited (free)
Cache TTL: 6h
"""

import asyncio
import logging
from typing import Dict, Any, Optional

import aiohttp

from ..ti_cache import get_ti_cache

logger = logging.getLogger(__name__)

OTX_BASE = "https://otx.alienvault.com/api/v1"
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]


class OTXProvider:
    """AlienVault OTX threat intelligence provider."""

    def __init__(self):
        self.cache = get_ti_cache()
        self.provider = "otx"

    def _get_api_key(self) -> Optional[str]:
        return self.cache.get_api_key(self.provider, "OTX_API_KEY")

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        cached = self.cache.get(self.provider, f"ip:{ip}")
        if cached is not None:
            return cached

        # OTX general + geo sections
        general = await self._request(f"/indicators/IPv4/{ip}/general")
        result = self._parse_ip(general)
        self.cache.set(self.provider, f"ip:{ip}", result)
        return result

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        cached = self.cache.get(self.provider, f"hash:{file_hash}")
        if cached is not None:
            return cached

        # Determine hash type
        hash_type = "MD5" if len(file_hash) == 32 else "SHA256"
        general = await self._request(f"/indicators/file/{file_hash}/general")
        result = self._parse_file(general)
        self.cache.set(self.provider, f"hash:{file_hash}", result)
        return result

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        cached = self.cache.get(self.provider, f"domain:{domain}")
        if cached is not None:
            return cached

        general = await self._request(f"/indicators/domain/{domain}/general")
        result = self._parse_domain(general)
        self.cache.set(self.provider, f"domain:{domain}", result)
        return result

    async def _request(self, path: str) -> Optional[Dict]:
        api_key = self._get_api_key()
        if not api_key:
            logger.warning("OTX: no API key configured")
            return None

        headers = {"X-OTX-API-KEY": api_key}
        url = f"{OTX_BASE}{path}"

        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        elif resp.status == 404:
                            return None
                        elif resp.status in (401, 403):
                            logger.error(f"OTX: auth error {resp.status}")
                            return None
                        else:
                            logger.warning(f"OTX: HTTP {resp.status}, retry {attempt+1}")
            except asyncio.TimeoutError:
                logger.warning(f"OTX: timeout, retry {attempt+1}")
            except Exception as e:
                logger.warning(f"OTX: error {e}, retry {attempt+1}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)

        return None

    def _parse_ip(self, data: Optional[Dict]) -> Dict[str, Any]:
        if not data:
            return {"available": False}
        pulse_info = data.get("pulse_info", {})
        return {
            "available": True,
            "pulse_count": pulse_info.get("count", 0),
            "tags": list({tag for p in pulse_info.get("pulses", []) for tag in p.get("tags", [])}),
            "malware_families": list({
                mf for p in pulse_info.get("pulses", [])
                for mf in p.get("malware_families", [])
            }),
            "threat_hunter_score": data.get("threat_score", 0),
            "is_malicious": pulse_info.get("count", 0) > 0,
        }

    def _parse_file(self, data: Optional[Dict]) -> Dict[str, Any]:
        if not data:
            return {"available": False}
        pulse_info = data.get("pulse_info", {})
        return {
            "available": True,
            "pulse_count": pulse_info.get("count", 0),
            "tags": list({tag for p in pulse_info.get("pulses", []) for tag in p.get("tags", [])}),
            "malware_families": list({
                mf for p in pulse_info.get("pulses", [])
                for mf in p.get("malware_families", [])
            }),
            "is_malicious": pulse_info.get("count", 0) > 0,
        }

    def _parse_domain(self, data: Optional[Dict]) -> Dict[str, Any]:
        if not data:
            return {"available": False}
        pulse_info = data.get("pulse_info", {})
        return {
            "available": True,
            "pulse_count": pulse_info.get("count", 0),
            "tags": list({tag for p in pulse_info.get("pulses", []) for tag in p.get("tags", [])}),
            "is_malicious": pulse_info.get("count", 0) > 0,
        }
