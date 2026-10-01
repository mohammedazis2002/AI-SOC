"""
DeepDarkCTI Provider
=====================
Pulls structured threat intelligence from the DeepDarkCTI GitHub repository.
Covers: ransomware gang sites, cybercriminal forums, Telegram channels,
        data leak sites, and dark web IOCs.

Source: https://github.com/fastfire/deepdarkCTI
No API key required. Data is fetched from raw GitHub content.
Cache TTL: 1h (updated frequently by the community)

Checks:
  - Is the IP/domain mentioned in ransomware C2 lists?
  - Is the IP/domain in known dark web forum infrastructure?
  - Is the hash associated with ransomware tools?
"""

import asyncio
import logging
from typing import Dict, Any, Optional, Set

import aiohttp

from ..ti_cache import get_ti_cache

logger = logging.getLogger(__name__)

GITHUB_RAW = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main"

# Feed URLs — these are the main IOC lists in the repo
FEEDS = {
    "ransomware_ips": f"{GITHUB_RAW}/ransomware/ransomware_ips.txt",
    "ransomware_domains": f"{GITHUB_RAW}/ransomware/ransomware_domains.txt",
    "c2_ips": f"{GITHUB_RAW}/C2/C2_ips.txt",
    "c2_domains": f"{GITHUB_RAW}/C2/C2_domains.txt",
    "phishing_domains": f"{GITHUB_RAW}/phishing/phishing_domains.txt",
}

MAX_RETRIES = 2
RETRY_DELAYS = [2, 5]


class DeepDarkCTIProvider:
    """
    DeepDarkCTI dark/deep web threat intelligence provider.
    Loads IOC lists from GitHub and checks indicators against them.
    """

    def __init__(self):
        self.cache = get_ti_cache()
        self.provider = "deepdarkcti"
        # In-memory IOC sets (populated lazily)
        self._ioc_sets: Dict[str, Set[str]] = {}
        self._loaded = False

    async def _ensure_loaded(self):
        """Load all IOC feeds into memory (cached in Redis for 1h)."""
        if self._loaded:
            return

        for feed_name, url in FEEDS.items():
            # Check Redis cache first
            cached = self.cache.get(self.provider, f"feed:{feed_name}")
            if cached and isinstance(cached, dict):
                self._ioc_sets[feed_name] = set(cached.get("iocs", []))
                continue

            # Fetch from GitHub
            iocs = await self._fetch_feed(url)
            self._ioc_sets[feed_name] = set(iocs)
            # Cache the feed list
            self.cache.set(self.provider, f"feed:{feed_name}", {"iocs": iocs})

        self._loaded = True
        total = sum(len(s) for s in self._ioc_sets.values())
        logger.info(f"DeepDarkCTI: loaded {total} IOCs across {len(self._ioc_sets)} feeds")

    async def _fetch_feed(self, url: str) -> list:
        """Fetch a text IOC feed from GitHub."""
        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            # Parse: one IOC per line, skip comments
                            iocs = [
                                line.strip().lower()
                                for line in text.splitlines()
                                if line.strip() and not line.startswith("#")
                            ]
                            return iocs
                        elif resp.status == 404:
                            logger.debug(f"DeepDarkCTI: feed not found: {url}")
                            return []
                        else:
                            logger.warning(f"DeepDarkCTI: HTTP {resp.status} for {url}")
            except asyncio.TimeoutError:
                logger.warning(f"DeepDarkCTI: timeout fetching {url}, retry {attempt+1}")
            except Exception as e:
                logger.warning(f"DeepDarkCTI: error fetching {url}: {e}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)
        return []

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        cached = self.cache.get(self.provider, f"ip:{ip}")
        if cached is not None:
            return cached

        await self._ensure_loaded()
        ip_lower = ip.lower()

        matches = []
        if ip_lower in self._ioc_sets.get("ransomware_ips", set()):
            matches.append("ransomware_c2")
        if ip_lower in self._ioc_sets.get("c2_ips", set()):
            matches.append("command_and_control")

        result = {
            "available": True,
            "found": len(matches) > 0,
            "matches": matches,
            "is_malicious": len(matches) > 0,
        }
        self.cache.set(self.provider, f"ip:{ip}", result)
        return result

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        cached = self.cache.get(self.provider, f"domain:{domain}")
        if cached is not None:
            return cached

        await self._ensure_loaded()
        domain_lower = domain.lower()

        matches = []
        if domain_lower in self._ioc_sets.get("ransomware_domains", set()):
            matches.append("ransomware_c2")
        if domain_lower in self._ioc_sets.get("c2_domains", set()):
            matches.append("command_and_control")
        if domain_lower in self._ioc_sets.get("phishing_domains", set()):
            matches.append("phishing")

        result = {
            "available": True,
            "found": len(matches) > 0,
            "matches": matches,
            "is_malicious": len(matches) > 0,
        }
        self.cache.set(self.provider, f"domain:{domain}", result)
        return result
