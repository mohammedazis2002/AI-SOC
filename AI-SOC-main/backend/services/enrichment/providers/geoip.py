"""
GeoIP Provider
==============
Lookups: Country, city, ASN, org, timezone for IPs
Primary: ip-api.com (free, no key, 45 req/min)
Cache TTL: 7 days (geo data rarely changes)
"""

import asyncio
import logging
from typing import Dict, Any, Optional

import aiohttp

from ..ti_cache import get_ti_cache

logger = logging.getLogger(__name__)

GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]

# RFC1918 private ranges — skip geo lookup
PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "::1", "fc", "fd")
PRIVATE_RANGES_172 = range(16, 32)


def _is_private_ip(ip: str) -> bool:
    if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
        return True
    # 172.16.0.0/12
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if second_octet in PRIVATE_RANGES_172:
                return True
        except (IndexError, ValueError):
            pass
    return False


class GeoIPProvider:
    """GeoIP provider using ip-api.com (free, no key required)."""

    def __init__(self):
        self.cache = get_ti_cache()
        self.provider = "geoip"

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if _is_private_ip(ip):
            return {"available": True, "private": True, "country": "Private", "ip": ip}

        cached = self.cache.get(self.provider, f"ip:{ip}")
        if cached is not None:
            return cached

        result = await self._fetch(ip)
        self.cache.set(self.provider, f"ip:{ip}", result)
        return result

    async def _fetch(self, ip: str) -> Dict[str, Any]:
        url = GEOIP_URL.format(ip=ip)

        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return self._parse(data)
                        elif resp.status == 429:
                            logger.warning(f"GeoIP: rate limited, retry {attempt+1}")
                        else:
                            logger.warning(f"GeoIP: HTTP {resp.status}")
            except asyncio.TimeoutError:
                logger.warning(f"GeoIP: timeout, retry {attempt+1}")
            except Exception as e:
                logger.warning(f"GeoIP: error {e}, retry {attempt+1}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)

        return {"available": False}

    def _parse(self, data: Dict) -> Dict[str, Any]:
        if data.get("status") != "success":
            return {"available": False, "error": data.get("message", "unknown")}
        return {
            "available": True,
            "ip": data.get("query", ""),
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "timezone": data.get("timezone", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "asn": data.get("as", ""),
            "asn_name": data.get("asname", ""),
            "is_mobile": data.get("mobile", False),
            "is_proxy": data.get("proxy", False),
            "is_hosting": data.get("hosting", False),
        }
