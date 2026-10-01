"""
GreyNoise Provider
==================
Lookups: IP classification (malicious/benign/unknown), noise/RIOT tags
Community API: free, no key (basic)
Full API: GREYNOISE_API_KEY env var
Cache TTL: 4h
"""

import asyncio
import logging
import os
from typing import Dict, Any, Optional

import aiohttp

from ..ti_cache import get_ti_cache

logger = logging.getLogger(__name__)

GN_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
GN_FULL_URL = "https://api.greynoise.io/v2/noise/context/{ip}"
GN_RIOT_URL = "https://api.greynoise.io/v2/riot/{ip}"

MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]


class GreyNoiseProvider:
    """GreyNoise IP classification provider."""

    def __init__(self):
        self.cache = get_ti_cache()
        self.provider = "greynoise"

    def _get_api_key(self) -> Optional[str]:
        return self.cache.get_api_key(self.provider, "GREYNOISE_API_KEY")

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        cached = self.cache.get(self.provider, f"ip:{ip}")
        if cached is not None:
            return cached

        api_key = self._get_api_key()

        if api_key:
            # Full API — more detail
            noise, riot = await asyncio.gather(
                self._fetch(GN_FULL_URL.format(ip=ip), api_key),
                self._fetch(GN_RIOT_URL.format(ip=ip), api_key),
                return_exceptions=True
            )
            result = self._parse_full(
                noise if not isinstance(noise, Exception) else None,
                riot if not isinstance(riot, Exception) else None
            )
        else:
            # Community API — basic classification
            data = await self._fetch(GN_COMMUNITY_URL.format(ip=ip), None)
            result = self._parse_community(data)

        self.cache.set(self.provider, f"ip:{ip}", result)
        return result

    async def _fetch(self, url: str, api_key: Optional[str]) -> Optional[Dict]:
        headers = {}
        if api_key:
            headers["key"] = api_key

        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        elif resp.status == 404:
                            return {"not_found": True}
                        elif resp.status in (401, 403):
                            # Paid endpoint returned auth error — key is community-tier.
                            # Fall back to /v3/community which is free for all valid keys.
                            if "/v2/" in url:
                                ip = url.rstrip("/").split("/")[-1]
                                logger.info(
                                    f"GreyNoise: key is community-tier, "
                                    f"falling back to /v3/community for {ip}"
                                )
                                comm_url = GN_COMMUNITY_URL.format(ip=ip)
                                return await self._fetch(comm_url, api_key)
                            logger.error(f"GreyNoise: auth error {resp.status}")
                            return None
                        elif resp.status == 429:
                            logger.warning(f"GreyNoise: rate limited, retry {attempt+1}")
                        else:
                            logger.warning(f"GreyNoise: HTTP {resp.status}, retry {attempt+1}")
            except asyncio.TimeoutError:
                logger.warning(f"GreyNoise: timeout, retry {attempt+1}")
            except Exception as e:
                logger.warning(f"GreyNoise: error {e}, retry {attempt+1}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)
        return None

    def _parse_community(self, data: Optional[Dict]) -> Dict[str, Any]:
        if not data or data.get("not_found"):
            return {"available": True, "classification": "unknown", "noise": False, "riot": False}
        return {
            "available": True,
            "ip": data.get("ip", ""),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name", ""),
            "link": data.get("link", ""),
            "last_seen": data.get("last_seen", ""),
            "message": data.get("message", ""),
            "is_malicious": data.get("classification") == "malicious",
        }

    def _parse_full(self, noise: Optional[Dict], riot: Optional[Dict]) -> Dict[str, Any]:
        result = {"available": True}

        if noise and not noise.get("not_found"):
            result.update({
                "noise": noise.get("seen", False),
                "classification": noise.get("classification", "unknown"),
                "name": noise.get("name", ""),
                "tags": noise.get("tags", []),
                "last_seen": noise.get("last_seen", ""),
                "country": noise.get("metadata", {}).get("country", ""),
                "asn": noise.get("metadata", {}).get("asn", ""),
                "organization": noise.get("metadata", {}).get("organization", ""),
                "os": noise.get("metadata", {}).get("os", ""),
                "category": noise.get("metadata", {}).get("category", ""),
                "is_malicious": noise.get("classification") == "malicious",
            })
        else:
            result.update({"noise": False, "classification": "unknown", "is_malicious": False})

        if riot and not riot.get("not_found"):
            result["riot"] = riot.get("riot", False)
            result["riot_name"] = riot.get("name", "")
            result["riot_description"] = riot.get("description", "")
        else:
            result["riot"] = False

        return result
