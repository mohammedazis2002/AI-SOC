"""
Abuse.ch Provider
=================
Three services — free accounts required as of late 2024:
  - MalwareBazaar: file hash lookups    (https://bazaar.abuse.ch/api/)
  - ThreatFox: IP, domain, URL, hash    (https://threatfox.abuse.ch/api/)
  - URLhaus: malicious URL/domain/IP   (https://urlhaus-api.abuse.ch/)

Get free API keys at: https://auth.abuse.ch/
Set env vars: THREATFOX_API_KEY, URLHAUS_API_KEY, MALWAREBAZAAR_API_KEY

Cache TTL: 1h (feeds update hourly)
"""

import asyncio
import logging
import os
from typing import Dict, Any, Optional, List

import aiohttp

from ..ti_cache import get_ti_cache

logger = logging.getLogger(__name__)

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"

MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]


class AbuseCHProvider:
    """Abuse.ch provider: MalwareBazaar + ThreatFox + URLhaus."""

    def __init__(self):
        self.cache = get_ti_cache()
        self.provider = "abusech"
        # Auth keys — free accounts at https://auth.abuse.ch/
        self._tf_key  = os.getenv("THREATFOX_API_KEY") or os.getenv("ABUSECH_API_KEY")
        self._uh_key  = os.getenv("URLHAUS_API_KEY")   or os.getenv("ABUSECH_API_KEY")
        self._mb_key  = os.getenv("MALWAREBAZAAR_API_KEY") or os.getenv("ABUSECH_API_KEY")
        if not self._tf_key:
            logger.warning("AbuseCH: no THREATFOX_API_KEY — ThreatFox lookups will return 401. "
                           "Get a free key at https://auth.abuse.ch/")

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up file hash in MalwareBazaar + ThreatFox."""
        cached = self.cache.get(self.provider, f"hash:{file_hash}")
        if cached is not None:
            return cached

        mb, tf = await asyncio.gather(
            self._malwarebazaar_hash(file_hash),
            self._threatfox_ioc(file_hash, "payload"),
            return_exceptions=True
        )
        result = {
            "available": True,
            "malwarebazaar": mb if not isinstance(mb, Exception) else None,
            "threatfox": tf if not isinstance(tf, Exception) else None,
            "is_malicious": bool(
                (isinstance(mb, dict) and mb.get("found")) or
                (isinstance(tf, dict) and tf.get("found"))
            ),
        }
        self.cache.set(self.provider, f"hash:{file_hash}", result)
        return result

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up IP in ThreatFox + URLhaus."""
        cached = self.cache.get(self.provider, f"ip:{ip}")
        if cached is not None:
            return cached

        tf, uh = await asyncio.gather(
            self._threatfox_ioc(ip, "ip:port"),
            self._urlhaus_host(ip),
            return_exceptions=True
        )
        result = {
            "available": True,
            "threatfox": tf if not isinstance(tf, Exception) else None,
            "urlhaus": uh if not isinstance(uh, Exception) else None,
            "is_malicious": bool(
                (isinstance(tf, dict) and tf.get("found")) or
                (isinstance(uh, dict) and uh.get("found"))
            ),
        }
        self.cache.set(self.provider, f"ip:{ip}", result)
        return result

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        """Look up URL in URLhaus."""
        cached = self.cache.get(self.provider, f"url:{url}")
        if cached is not None:
            return cached

        result_raw = await self._urlhaus_url(url)
        result = {
            "available": True,
            "urlhaus": result_raw,
            "is_malicious": bool(result_raw and result_raw.get("found")),
        }
        self.cache.set(self.provider, f"url:{url}", result)
        return result

    # ── MalwareBazaar ────────────────────────────────────────────────────────

    async def _malwarebazaar_hash(self, file_hash: str) -> Dict[str, Any]:
        payload = {"query": "get_info", "hash": file_hash}
        if self._mb_key:
            payload["anonymous"] = "0"
        data = await self._post(MALWAREBAZAAR_URL, payload, auth_key=self._mb_key)
        if not data or data.get("query_status") != "hash_found":
            return {"found": False}
        sample = data.get("data", [{}])[0]
        return {
            "found": True,
            "sha256": sample.get("sha256_hash"),
            "md5": sample.get("md5_hash"),
            "file_name": sample.get("file_name"),
            "file_type": sample.get("file_type_mime"),
            "signature": sample.get("signature"),
            "tags": sample.get("tags", []),
            "first_seen": sample.get("first_seen"),
            "reporter": sample.get("reporter"),
        }

    # ── ThreatFox ────────────────────────────────────────────────────────────

    async def _threatfox_ioc(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        payload = {"query": "search_ioc", "search_term": ioc}
        data = await self._post(THREATFOX_URL, payload, auth_key=self._tf_key)
        if not data or data.get("query_status") != "ok":
            return {"found": False}
        results = data.get("data", [])
        if not results:
            return {"found": False}
        first = results[0]
        return {
            "found": True,
            "ioc_type": first.get("ioc_type"),
            "threat_type": first.get("threat_type"),
            "malware": first.get("malware"),
            "malware_alias": first.get("malware_alias"),
            "confidence": first.get("confidence_level"),
            "first_seen": first.get("first_seen"),
            "last_seen": first.get("last_seen"),
            "tags": first.get("tags", []),
            "total_matches": len(results),
        }

    # ── URLhaus ──────────────────────────────────────────────────────────────

    async def _urlhaus_host(self, host: str) -> Dict[str, Any]:
        payload = {"host": host}
        data = await self._post(URLHAUS_URL + "host/", payload, auth_key=self._uh_key)
        if not data or data.get("query_status") != "is_host":
            return {"found": False}
        urls = data.get("urls", [])
        return {
            "found": True,
            "url_count": len(urls),
            "tags": list({tag for u in urls for tag in (u.get("tags") or [])}),
            "blacklists": data.get("blacklists", {}),
        }

    async def _urlhaus_url(self, url: str) -> Dict[str, Any]:
        payload = {"url": url}
        data = await self._post(URLHAUS_URL + "url/", payload, auth_key=self._uh_key)
        if not data or data.get("query_status") != "is_listed":
            return {"found": False}
        return {
            "found": True,
            "url_status": data.get("url_status"),
            "threat": data.get("threat"),
            "tags": data.get("tags", []),
            "blacklists": data.get("blacklists", {}),
        }

    # ── HTTP helper ──────────────────────────────────────────────────────────

    async def _post(self, url: str, payload: Dict, auth_key: Optional[str] = None) -> Optional[Dict]:
        """
        POST to an Abuse.ch API endpoint.
        Auth-Key is sent as HTTP header (abuse.ch v1 standard since 2024).
        """
        headers = {}
        if auth_key:
            headers["Auth-Key"] = auth_key

        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url, data=payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False    # bypass Windows cert store issues with abuse.ch
                    ) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        elif resp.status == 401:
                            logger.warning(
                                f"Abuse.ch {url}: 401 Unauthorized. "
                                f"Get a free API key at https://auth.abuse.ch/ and set "
                                f"THREATFOX_API_KEY / URLHAUS_API_KEY / MALWAREBAZAAR_API_KEY"
                            )
                            return None  # Skip retries on auth failure
                        else:
                            logger.warning(f"Abuse.ch {url}: HTTP {resp.status}, retry {attempt+1}")
            except asyncio.TimeoutError:
                logger.warning(f"Abuse.ch {url}: timeout, retry {attempt+1}")
            except Exception as e:
                logger.warning(f"Abuse.ch {url}: error {e}, retry {attempt+1}")

            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)
        return None
