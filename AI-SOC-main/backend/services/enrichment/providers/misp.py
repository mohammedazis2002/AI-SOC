"""
MISP Provider
=============
Queries a MISP instance for IOC matches (IP, domain, hash, URL).
Supports both self-hosted MISP and community MISP servers.

Config:
  MISP_URL=https://your-misp-instance
  MISP_API_KEY=your_key
  MISP_VERIFY_SSL=true (set to false for self-signed certs)

Cache TTL: 1h (MISP events update frequently)
"""

import asyncio
import logging
import os
from typing import Dict, Any, Optional, List

import aiohttp

from ..ti_cache import get_ti_cache

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]


class MISPProvider:
    """MISP threat intelligence platform provider."""

    def __init__(self):
        self.cache = get_ti_cache()
        self.provider = "misp"
        self.base_url = os.getenv("MISP_URL", "").rstrip("/")
        self.verify_ssl = os.getenv("MISP_VERIFY_SSL", "true").lower() != "false"

    def _get_api_key(self) -> Optional[str]:
        return self.cache.get_api_key(self.provider, "MISP_API_KEY")

    def _is_configured(self) -> bool:
        return bool(self.base_url and self._get_api_key())

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if not self._is_configured():
            return {"available": False, "skipped": True, "reason": "MISP not configured"}

        cached = self.cache.get(self.provider, f"ip:{ip}")
        if cached is not None:
            return cached

        result = await self._search_attribute("ip-dst|ip-src|ip-dst/src", ip)
        self.cache.set(self.provider, f"ip:{ip}", result)
        return result

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        if not self._is_configured():
            return {"available": False, "skipped": True, "reason": "MISP not configured"}

        cached = self.cache.get(self.provider, f"hash:{file_hash}")
        if cached is not None:
            return cached

        # Search across all hash types
        result = await self._search_attribute("md5|sha1|sha256|sha512", file_hash)
        self.cache.set(self.provider, f"hash:{file_hash}", result)
        return result

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        if not self._is_configured():
            return {"available": False, "skipped": True, "reason": "MISP not configured"}

        cached = self.cache.get(self.provider, f"domain:{domain}")
        if cached is not None:
            return cached

        result = await self._search_attribute("domain|hostname", domain)
        self.cache.set(self.provider, f"domain:{domain}", result)
        return result

    async def _search_attribute(self, attr_type: str, value: str) -> Dict[str, Any]:
        """Search MISP for a specific attribute value."""
        api_key = self._get_api_key()
        url = f"{self.base_url}/attributes/restSearch"
        headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        # Search across multiple attribute types
        types = [t.strip() for t in attr_type.split("|")]
        payload = {
            "returnFormat": "json",
            "value": value,
            "type": types,
            "includeEventTags": True,
            "limit": 20,
        }

        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.post(
                        url, headers=headers, json=payload,
                        timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return self._parse(data, value)
                        elif resp.status in (401, 403):
                            logger.error(f"MISP: auth error {resp.status}")
                            return {"available": False, "error": f"Auth error {resp.status}"}
                        elif resp.status == 404:
                            return {"available": True, "found": False, "event_count": 0}
                        else:
                            logger.warning(f"MISP: HTTP {resp.status}, retry {attempt+1}")
            except asyncio.TimeoutError:
                logger.warning(f"MISP: timeout, retry {attempt+1}")
            except Exception as e:
                logger.warning(f"MISP: error {e}, retry {attempt+1}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)

        return {"available": False, "error": "All retries failed"}

    def _parse(self, data: Dict, searched_value: str) -> Dict[str, Any]:
        attributes = data.get("response", {}).get("Attribute", [])
        if not attributes:
            return {"available": True, "found": False, "event_count": 0}

        # Collect unique events
        event_ids = set()
        tags = set()
        threat_levels = []
        categories = set()

        for attr in attributes:
            event_ids.add(attr.get("event_id"))
            categories.add(attr.get("category", ""))
            for tag in attr.get("EventTag", []):
                tag_name = tag.get("Tag", {}).get("name", "")
                if tag_name:
                    tags.add(tag_name)
            # Threat level from event
            event = attr.get("Event", {})
            if event.get("threat_level_id"):
                threat_levels.append(int(event["threat_level_id"]))

        # MISP threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined
        min_threat = min(threat_levels) if threat_levels else 4
        threat_map = {1: "high", 2: "medium", 3: "low", 4: "undefined"}

        return {
            "available": True,
            "found": True,
            "event_count": len(event_ids),
            "attribute_count": len(attributes),
            "threat_level": threat_map.get(min_threat, "undefined"),
            "categories": list(categories),
            "tags": list(tags)[:20],
            "is_malicious": min_threat <= 2,  # High or Medium threat
        }
