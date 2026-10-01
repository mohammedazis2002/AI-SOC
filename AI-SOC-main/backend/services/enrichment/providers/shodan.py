"""
Shodan Provider
===============
Lookups: Open ports, vulnerabilities, tags, hostnames for IPs
API: https://api.shodan.io/
Rate limit: 1 req/sec (free tier)
Cache TTL: 24h
"""

import asyncio
import logging
from typing import Dict, Any, Optional

import aiohttp

from ..ti_cache import get_ti_cache

logger = logging.getLogger(__name__)

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]


class ShodanProvider:
    """Shodan internet scan data provider."""

    def __init__(self):
        self.cache = get_ti_cache()
        self.provider = "shodan"

    def _get_api_key(self) -> Optional[str]:
        return self.cache.get_api_key(self.provider, "SHODAN_API_KEY")

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        api_key = self._get_api_key()
        if not api_key:
            logger.debug("Shodan: no API key configured, skipping")
            return {"available": False, "skipped": True}

        cached = self.cache.get(self.provider, f"ip:{ip}")
        if cached is not None:
            return cached

        result = await self._fetch(ip, api_key)
        self.cache.set(self.provider, f"ip:{ip}", result)
        return result

    async def _fetch(self, ip: str, api_key: str) -> Dict[str, Any]:
        url = SHODAN_HOST_URL.format(ip=ip)
        params = {"key": api_key}

        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, params=params,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return self._parse(data)
                        elif resp.status == 404:
                            return {"available": True, "found": False}
                        elif resp.status in (401, 403):
                            logger.error(f"Shodan: auth error {resp.status}")
                            return {"available": False}
                        elif resp.status == 429:
                            logger.warning(f"Shodan: rate limited, retry {attempt+1}")
                        else:
                            logger.warning(f"Shodan: HTTP {resp.status}, retry {attempt+1}")
            except asyncio.TimeoutError:
                logger.warning(f"Shodan: timeout, retry {attempt+1}")
            except Exception as e:
                logger.warning(f"Shodan: error {e}, retry {attempt+1}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)

        return {"available": False}

    def _parse(self, data: Dict) -> Dict[str, Any]:
        ports = data.get("ports", [])
        vulns = list(data.get("vulns", {}).keys())
        hostnames = data.get("hostnames", [])
        tags = data.get("tags", [])
        org = data.get("org", "")
        isp = data.get("isp", "")
        country = data.get("country_name", "")
        asn = data.get("asn", "")

        # Extract service banners
        services = []
        for item in data.get("data", []):
            svc = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
            }
            services.append(svc)

        return {
            "available": True,
            "found": True,
            "ip": data.get("ip_str", ""),
            "ports": ports,
            "open_port_count": len(ports),
            "vulns": vulns,
            "vuln_count": len(vulns),
            "hostnames": hostnames,
            "tags": tags,
            "org": org,
            "isp": isp,
            "country": country,
            "asn": asn,
            "services": services[:10],  # Top 10 services
            "last_update": data.get("last_update", ""),
            "is_malicious": len(vulns) > 0 or "malware" in tags,
        }
