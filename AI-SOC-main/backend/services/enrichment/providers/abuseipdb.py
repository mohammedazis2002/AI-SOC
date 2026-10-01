"""
AbuseIPDB Provider
==================
Lookups: IP abuse confidence score, report count, attack categories
API: https://api.abuseipdb.com/api/v2/
Rate limit: 1000 req/day (free)
Cache TTL: 24h
"""

import asyncio
import logging
from typing import Dict, Any, Optional

import aiohttp

from ..ti_cache import get_ti_cache

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]

# AbuseIPDB category codes → human-readable names
CATEGORY_NAMES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


class AbuseIPDBProvider:
    """AbuseIPDB IP reputation provider."""

    def __init__(self):
        self.cache = get_ti_cache()
        self.provider = "abuseipdb"

    def _get_api_key(self) -> Optional[str]:
        return self.cache.get_api_key(self.provider, "ABUSEIPDB_API_KEY")

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        cached = self.cache.get(self.provider, f"ip:{ip}")
        if cached is not None:
            return cached

        result = await self._check_ip(ip)
        self.cache.set(self.provider, f"ip:{ip}", result)
        return result

    async def _check_ip(self, ip: str) -> Dict[str, Any]:
        api_key = self._get_api_key()
        if not api_key:
            logger.warning("AbuseIPDB: no API key configured")
            return {"available": False}

        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
        url = f"{ABUSEIPDB_BASE}/check"

        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, headers=headers, params=params,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return self._parse(data)
                        elif resp.status == 422:
                            # Private IP or invalid
                            return {"available": True, "private_ip": True, "confidence": 0}
                        elif resp.status in (401, 403):
                            logger.error(f"AbuseIPDB: auth error {resp.status}")
                            return {"available": False}
                        elif resp.status == 429:
                            logger.warning(f"AbuseIPDB: rate limited, retry {attempt+1}")
                        else:
                            logger.warning(f"AbuseIPDB: HTTP {resp.status}, retry {attempt+1}")
            except asyncio.TimeoutError:
                logger.warning(f"AbuseIPDB: timeout, retry {attempt+1}")
            except Exception as e:
                logger.warning(f"AbuseIPDB: error {e}, retry {attempt+1}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)

        return {"available": False}

    def _parse(self, data: Dict) -> Dict[str, Any]:
        d = data.get("data", {})
        category_ids = d.get("usageType", [])
        # Reports contain category IDs
        reports = d.get("reports", [])
        cat_ids = set()
        for r in reports:
            cat_ids.update(r.get("categories", []))

        confidence = d.get("abuseConfidenceScore", 0)
        return {
            "available": True,
            "ip": d.get("ipAddress", ""),
            "confidence": confidence,
            "total_reports": d.get("totalReports", 0),
            "distinct_users": d.get("numDistinctUsers", 0),
            "last_reported": d.get("lastReportedAt"),
            "country": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "usage_type": d.get("usageType", ""),
            "categories": [CATEGORY_NAMES.get(c, str(c)) for c in cat_ids],
            "is_tor": d.get("isTor", False),
            "is_malicious": confidence >= 25,
        }
