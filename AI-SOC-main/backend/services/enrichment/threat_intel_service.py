"""
Threat Intelligence Orchestration Service  — v3 (Industry Grade)
=================================================================
Key improvements over v2:
  • DeepDarkCTI wired as 7th active provider (free, no API key)
    - Ransomware C2 IPs/domains, dark web forums, phishing infra
  • All indicators enriched  — up to MAX_IPS/HASHES/DOMAINS/URLS per alert
  • All 7 active providers scored per indicator in parallel
  • Corroboration multiplier  — multi-source agreement boosts confidence
  • OCSF/group-aware role weights — dst IP scores high for exfiltration alerts
  • Temporal freshness decay  — 7-tier non-zero curve applied to each hit
  • GeoIP and GreyNoise contribute to aggregate score (not context-only)
  • GreyNoise RIOT soft suppressor (0.15×) — near-zero, not zero
  • IOC co-occurrence amplifier — IP+hash both flagged → +0.10 alert bonus
  • URL scoring — AbuseCH URLhaus feeds the aggregate

Active providers (7):
  VirusTotal, OTX, AbuseIPDB, GeoIP, Abuse.ch, GreyNoise, DeepDarkCTI

Removed providers:
  Shodan — free tier blocked (HTTP 403 on /shodan/host/), paid tier only

Deferred providers (not yet wired):
  MISP — requires self-hosted MISP instance
  OpenCTI — requires self-hosted OpenCTI instance
"""

import asyncio
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple

from .providers.virustotal import VirusTotalProvider
from .providers.otx import OTXProvider
from .providers.abuseipdb import AbuseIPDBProvider
from .providers.geoip import GeoIPProvider
from .providers.abusech import AbuseCHProvider
from .providers.greynoise import GreyNoiseProvider
from .providers.deepdarkcti import DeepDarkCTIProvider

logger = logging.getLogger(__name__)

# ── Limits ────────────────────────────────────────────────────────────────────
# Configurable per-alert caps to stay within API rate limits
MAX_IPS      = 5
MAX_HASHES   = 5
MAX_DOMAINS  = 5
MAX_URLS     = 5

# ── Private IP detection ──────────────────────────────────────────────────────
PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "::1", "fc", "fd")
PRIVATE_172 = range(16, 32)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

HIGH_RISK_COUNTRIES = {
    "CN", "RU", "KP", "IR", "BY", "VN", "NG", "SY", "CU", "YE", "LY", "IQ", "MM"
}

# ── Alert group → role mapping ────────────────────────────────────────────────
# Determines role multiplier: how much each IP direction contributes to aggregate
# (src_weight, dst_weight)
_GROUP_ROLES: Dict[str, Tuple[float, float]] = {
    "data_exfiltration":    (0.5,  1.0),   # dst = attacker's C2 receiving server
    "exfiltration":         (0.5,  1.0),
    "command_and_control":  (0.7,  1.0),   # dst = C2 server
    "authentication":       (1.0,  0.2),   # src = brute-forcer
    "network":              (1.0,  0.5),   # generic network — src usually initiator
    "web":                  (1.0,  0.3),
    "malware":              (1.0,  0.6),
    "persistence":          (0.8,  0.8),
    "privilege_escalation": (1.0,  0.6),
    "reconnaissance":       (1.0,  0.3),
    "lateral_movement":     (1.0,  0.8),
    "zero_day":             (1.0,  0.7),
    "impact":               (1.0,  0.5),
}

# ── Provider weights ─────────────────────────────────────────────────────────
# Weighted average, normalized by responding providers.
# Weights reflect: crowdsourced breadth, false-positive rate, data freshness.
# Note: weights are normalized per responding provider — no need to sum to 1.0
SCORE_WEIGHTS: Dict[str, float] = {
    "virustotal":   0.26,   # 70+ AV engines, gold standard, very low FP rate
    "abuseipdb":    0.19,   # well-calibrated confidence %, large community
    "greynoise":    0.14,   # definitive when it fires malicious; RIOT suppression
    "otx":          0.15,   # good breadth, slightly noisy — normalized to 10 pulses
    "abusech":      0.16,   # high-precision malware feeds (MB + ThreatFox + URLhaus)
    "geoip":        0.04,   # proxy/hosting/high-risk-country flags
    "deepdarkcti":  0.06,   # free dark web / ransomware C2 / phishing feeds (GitHub)
}

MALICIOUS_THRESHOLD = 0.40     # alert declared malicious above this

# ── Corroboration ─────────────────────────────────────────────────────────────
CORROBORATION_PER_PROVIDER = 0.15   # +15% per agreeing provider
CORROBORATION_CAP = 1.75            # maximum multiplier

# ── Temporal decay tiers ─────────────────────────────────────────────────────
# (max_days, multiplier) — checked in order, first match wins
FRESHNESS_TIERS: List[Tuple[int, float]] = [
    (7,   1.25),
    (30,  1.00),
    (90,  0.85),
    (180, 0.70),
    (365, 0.55),
    (9999, 0.40),   # > 365 days — non-zero floor
]
FRESHNESS_NO_DATE = 0.90   # slight penalty for missing last_seen metadata


def _is_private_ip(ip: str) -> bool:
    if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            if int(ip.split(".")[1]) in PRIVATE_172:
                return True
        except (IndexError, ValueError):
            pass
    return False


def _freshness_multiplier(date_str: Optional[str]) -> float:
    """Return a decay multiplier based on how recently an IOC was last seen."""
    if not date_str:
        return FRESHNESS_NO_DATE
    # Attempt to parse ISO-style datetime strings
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str[:19], fmt)
            age_days = (datetime.now() - dt).days
            for max_days, multiplier in FRESHNESS_TIERS:
                if age_days <= max_days:
                    return multiplier
        except ValueError:
            continue
    return FRESHNESS_NO_DATE


def _detect_role_weights(alert: Dict) -> Tuple[float, float]:
    """Return (src_weight, dst_weight) based on alert rule groups."""
    groups = alert.get("rule", {}).get("groups", [])
    # Check groups in the order they appear; first match wins
    for g in groups:
        g_lower = g.lower()
        for key, weights in _GROUP_ROLES.items():
            if key in g_lower:
                return weights
    return (0.8, 0.8)   # symmetric default — unknown context


def _extract_indicators(alert: Dict) -> Dict[str, List[Dict]]:
    """
    Exhaustively extract indicators from a Wazuh/ULF alert dict.

    Returns:
        {
          "ips":     [{"value": "1.2.3.4", "role": "src"|"dst"|"other", "field": "..."}],
          "hashes":  [{"value": "abc...",  "role": "file|process",      "field": "..."}],
          "domains": [...],
          "urls":    [...],
        }
    Priority ordering: src IPs first, then dst, then others.
    """
    ips_raw: List[Dict]     = []
    hashes_raw: List[Dict]  = []
    domains_raw: List[Dict] = []
    urls_raw: List[Dict]    = []
    seen_ips: Set[str]      = set()
    seen_hashes: Set[str]   = set()
    seen_domains: Set[str]  = set()
    seen_urls: Set[str]     = set()

    def _add_ip(value: str, role: str, field: str):
        value = value.strip()
        if not value or value in seen_ips:
            return
        if _is_private_ip(value):
            return
        seen_ips.add(value)
        ips_raw.append({"value": value, "role": role, "field": field})

    def _add_hash(value: str, role: str, field: str):
        value = value.strip().lower()
        if not value or value in seen_hashes or len(value) not in (32, 40, 64, 128):
            return
        seen_hashes.add(value)
        hashes_raw.append({"value": value, "role": role, "field": field})

    def _add_domain(value: str, role: str, field: str):
        value = value.strip().lower()
        if not value or value in seen_domains:
            return
        # Skip bare IPs or localhost — these shouldn't be domain indicators.
        # IPs that reach here (from non-URL paths) are handled by _add_ip.
        if _IP_RE.fullmatch(value) or value in ("localhost", "localdomain"):
            return
        seen_domains.add(value)
        domains_raw.append({"value": value, "role": role, "field": field})

    def _add_url(value: str, role: str, field: str):
        value = value.strip()
        if not value or value in seen_urls:
            return
        # Skip URLs whose hostname is a private/internal IP — no TI value,
        # URLhaus won't have records for them.
        m = re.match(r"https?://([^/\?:]+)", value)
        if m:
            h = m.group(1)
            if _IP_RE.fullmatch(h) and _is_private_ip(h):
                return   # Internal IP URL — skip
        seen_urls.add(value)
        urls_raw.append({"value": value, "role": role, "field": field})

    data = alert.get("data", {})

    # ── IPs: src first (priority order) ──────────────────────────────────────
    # Wazuh-style: data.srcip / data.dstip
    if data.get("srcip"):
        _add_ip(data["srcip"], "src", "data.srcip")
    if data.get("dstip"):
        _add_ip(data["dstip"], "dst", "data.dstip")

    # ULF-style nested
    src_ep = alert.get("src_endpoint", {})
    dst_ep = alert.get("dst_endpoint", {})
    if src_ep.get("ip"):
        _add_ip(src_ep["ip"], "src", "src_endpoint.ip")
    if dst_ep.get("ip"):
        _add_ip(dst_ep["ip"], "dst", "dst_endpoint.ip")

    # Network activity
    net = alert.get("network_activity", {})
    if net.get("remote_ip"):
        _add_ip(net["remote_ip"], "other", "network_activity.remote_ip")
    conn = alert.get("connection", {})
    if conn.get("remote_ip"):
        _add_ip(conn["remote_ip"], "other", "connection.remote_ip")

    # Agent / manager IPs (internal but record for context)
    # Skip — agent.ip is always RFC1918

    # IP regex scan on full_log as last resort
    full_log = alert.get("full_log", "")
    for ip_match in _IP_RE.findall(full_log):
        _add_ip(ip_match, "other", "full_log")   # private filtered inside _add_ip

    # ── Hashes ───────────────────────────────────────────────────────────────
    # Wazuh flat: data.md5, data.sha256, data.sha1, data.sha512
    for htype in ("sha256", "sha1", "md5", "sha512"):
        val = data.get(htype)
        if val:
            _add_hash(val, "file", f"data.{htype}")

    # Nested: data.file.hashes.*
    file_hashes = data.get("file", {}).get("hashes", {}) if isinstance(data.get("file"), dict) else {}
    if not file_hashes and isinstance(data.get("file"), str):
        pass   # data.file is a path string, not a dict
    for htype in ("sha256", "sha1", "md5", "sha512"):
        val = file_hashes.get(htype)
        if val:
            _add_hash(val, "file", f"data.file.hashes.{htype}")

    # ULF nested: file.hashes.*
    ulff = alert.get("file", {})
    for htype in ("sha256", "sha1", "md5", "sha512"):
        val = ulff.get("hashes", {}).get(htype) if isinstance(ulff.get("hashes"), dict) else None
        if val:
            _add_hash(val, "file", f"file.hashes.{htype}")

    # Process file hashes
    proc = alert.get("process", {})
    for htype in ("sha256", "md5"):
        val = proc.get("file", {}).get("hashes", {}).get(htype) if isinstance(proc.get("file"), dict) else None
        if val:
            _add_hash(val, "process", f"process.file.hashes.{htype}")

    # ── Domains ──────────────────────────────────────────────────────────────
    if net.get("domain"):
        _add_domain(net["domain"], "c2", "network_activity.domain")
    dns = alert.get("dns", {})
    if dns.get("query", {}).get("name"):
        _add_domain(dns["query"]["name"], "dns_query", "dns.query.name")

    # ── URLs ─────────────────────────────────────────────────────────────────
    url = data.get("url") or net.get("url") or alert.get("http", {}).get("request", {}).get("url")
    if url:
        _add_url(url, "web_request", "data.url")
        # Extract hostname from URL — but only add as domain if it's NOT an IP address.
        # If it IS an IP (e.g. http://10.216.86.237/api), route through _add_ip
        # so that private-range filtering is applied and OTX/AbuseCH don't receive
        # raw IPs as domain lookups (which causes HTTP 400 errors).
        m = re.match(r"https?://([^/\?:]+)", url)
        if m:
            hostname = m.group(1)
            if _IP_RE.fullmatch(hostname):
                # It's an IP in a URL — treat as an IP indicator, not a domain
                _add_ip(hostname, "url_host_ip", "url_extracted_ip")
            else:
                _add_domain(hostname, "url_domain", "url_extracted_domain")

    # ── Apply caps — priority already embedded in order of insertion ──────
    return {
        "ips":     ips_raw[:MAX_IPS],
        "hashes":  hashes_raw[:MAX_HASHES],
        "domains": domains_raw[:MAX_DOMAINS],
        "urls":    urls_raw[:MAX_URLS],
    }


# ─────────────────────────────────────────────────────────────────────────────
class ThreatIntelService:
    """
    Threat intelligence enrichment orchestrator — v2.

    Usage:
        service = ThreatIntelService()
        result  = await service.enrich_alert(alert)
        # result stored in alert['enrichments']['threat_intel']
    """

    def __init__(self):
        self.vt           = VirusTotalProvider()
        self.otx          = OTXProvider()
        self.abuseipdb    = AbuseIPDBProvider()
        self.geoip        = GeoIPProvider()
        self.abusech      = AbuseCHProvider()
        self.greynoise    = GreyNoiseProvider()
        self.deepdarkcti  = DeepDarkCTIProvider()

    # ── Public API ────────────────────────────────────────────────────────────

    async def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich alert with threat intelligence. Modifies alert in-place."""
        if "enrichments" not in alert:
            alert["enrichments"] = {}
        try:
            result = await self._run(alert)
        except Exception as e:
            logger.error(f"TI enrichment failed: {e}", exc_info=True)
            result = {
                "available": False, "error": str(e),
                "aggregate_score": 0.0, "is_malicious": False,
            }
        alert["enrichments"]["threat_intel"] = result
        return alert

    async def enrich_ips(self, ips: List[str]) -> Dict[str, Any]:
        """Direct IP enrichment (called from alert_pipeline.py for quick lookups)."""
        fake_alert = {"data": {"srcip": ips[0]} if ips else {}}
        for i, ip in enumerate(ips[1:], 1):
            fake_alert["data"][f"ip_{i}"] = ip
        return await self._run(fake_alert)

    # ── Core pipeline ─────────────────────────────────────────────────────────

    async def _run(self, alert: Dict) -> Dict[str, Any]:
        indicators = _extract_indicators(alert)
        src_w, dst_w = _detect_role_weights(alert)

        all_ips     = indicators["ips"]
        all_hashes  = indicators["hashes"]
        all_domains = indicators["domains"]
        all_urls    = indicators["urls"]

        if not any([all_ips, all_hashes, all_domains, all_urls]):
            return {
                "available": False,
                "reason": "no_enrichable_indicators",
                "indicators": indicators,
                "aggregate_score": 0.0,
                "is_malicious": False,
                "enriched_at": datetime.now(timezone.utc).isoformat(),
            }

        logger.info(
            f"TI enrichment: {len(all_ips)} IPs, {len(all_hashes)} hashes, "
            f"{len(all_domains)} domains, {len(all_urls)} URLs — "
            f"role_weights=src:{src_w} dst:{dst_w}"
        )

        # ── Per-indicator parallel enrichment ─────────────────────────────────
        coros = {}

        for ioc in all_ips:
            ip = ioc["value"]
            coros[f"ip:{ip}"] = self._enrich_ip(ip)

        for ioc in all_hashes:
            h = ioc["value"]
            coros[f"hash:{h}"] = self._enrich_hash(h)

        for ioc in all_domains:
            d = ioc["value"]
            coros[f"domain:{d}"] = self._enrich_domain(d)

        for ioc in all_urls:
            u = ioc["value"]
            coros[f"url:{u}"] = self._enrich_url(u)

        keys = list(coros.keys())
        results_list = await asyncio.gather(*coros.values(), return_exceptions=True)
        raw_results = {
            k: (v if not isinstance(v, Exception) else {"available": False, "error": str(v)})
            for k, v in zip(keys, results_list)
        }

        # ── Build per-indicator summary ───────────────────────────────────────
        per_indicator: Dict[str, Any] = {}

        def _role_weight(ioc: Dict) -> float:
            role = ioc.get("role", "other")
            if role == "src":
                return src_w
            if role == "dst":
                return dst_w
            return 0.7   # other/process/dns/url

        for ioc in all_ips:
            ip = ioc["value"]
            data = raw_results.get(f"ip:{ip}", {})
            summary = self._summarise_indicator(ip, "ip", data, ioc)
            summary["role_weight"] = _role_weight(ioc)
            per_indicator[ip] = summary

        for ioc in all_hashes:
            h = ioc["value"]
            data = raw_results.get(f"hash:{h}", {})
            summary = self._summarise_indicator(h, "hash", data, ioc)
            summary["role_weight"] = _role_weight(ioc)
            per_indicator[h] = summary

        for ioc in all_domains:
            d = ioc["value"]
            data = raw_results.get(f"domain:{d}", {})
            summary = self._summarise_indicator(d, "domain", data, ioc)
            summary["role_weight"] = _role_weight(ioc)
            per_indicator[d] = summary

        for ioc in all_urls:
            u = ioc["value"]
            data = raw_results.get(f"url:{u}", {})
            summary = self._summarise_indicator(u, "url", data, ioc)
            summary["role_weight"] = _role_weight(ioc)
            per_indicator[u] = summary

        # ── Alert aggregate score ─────────────────────────────────────────────
        aggregate_score, top_indicators = self._compute_alert_score(per_indicator)

        # IOC co-occurrence amplifier — multiple indicator types flagged
        typed_malicious = set()
        for ioc in all_ips:
            if per_indicator.get(ioc["value"], {}).get("is_malicious"):
                typed_malicious.add("ip")
        for ioc in all_hashes:
            if per_indicator.get(ioc["value"], {}).get("is_malicious"):
                typed_malicious.add("hash")
        for ioc in all_domains:
            if per_indicator.get(ioc["value"], {}).get("is_malicious"):
                typed_malicious.add("domain")
        for ioc in all_urls:
            if per_indicator.get(ioc["value"], {}).get("is_malicious"):
                typed_malicious.add("url")

        co_occurrence_amplified = len(typed_malicious) >= 2
        if co_occurrence_amplified:
            aggregate_score = min(1.0, aggregate_score + 0.10)
            logger.info(f"IOC co-occurrence amplifier fired (+0.10): {typed_malicious}")

        is_malicious = aggregate_score >= MALICIOUS_THRESHOLD

        # ── Aggregate metadata ────────────────────────────────────────────────
        malware_families = list({
            fam
            for ind in per_indicator.values()
            for fam in ind.get("malware_families", [])
        })
        threat_categories = list({
            cat
            for ind in per_indicator.values()
            for cat in ind.get("threat_categories", [])
        })
        geo_primary = self._primary_geo(all_ips, per_indicator)
        infra_primary = self._primary_infra(all_ips, per_indicator)
        malicious_count = sum(
            1 for ind in per_indicator.values() if ind.get("is_malicious")
        )

        # Build provider_data keyed by IOC value (strip the type prefix)
        provider_data: Dict[str, Any] = {
            k.split(":", 1)[1]: v
            for k, v in raw_results.items()
        }

        return {
            "available": True,
            "indicators": indicators,
            "per_indicator": per_indicator,
            "provider_data": provider_data,
            "aggregate_score": round(aggregate_score, 3),
            "is_malicious": is_malicious,
            "malicious_indicator_count": malicious_count,
            "co_occurrence_amplified": co_occurrence_amplified,
            "top_threat_indicators": top_indicators,
            "malware_families": malware_families,
            "threat_categories": threat_categories,
            "geolocation_summary": geo_primary,
            "infrastructure_summary": infra_primary,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Provider dispatch ─────────────────────────────────────────────────────

    async def _enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Run all 7 active providers on a single IP in parallel."""
        results = await asyncio.gather(
            self.vt.lookup_ip(ip),
            self.otx.lookup_ip(ip),
            self.abuseipdb.lookup_ip(ip),
            self.geoip.lookup_ip(ip),
            self.abusech.lookup_ip(ip),
            self.greynoise.lookup_ip(ip),
            self.deepdarkcti.lookup_ip(ip),
            return_exceptions=True,
        )
        keys = ["virustotal", "otx", "abuseipdb", "geoip", "abusech", "greynoise", "deepdarkcti"]
        return {
            k: (v if not isinstance(v, Exception) else {"available": False, "error": str(v)})
            for k, v in zip(keys, results)
        }

    async def _enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """Run VT, OTX, AbuseCH on a file hash."""
        results = await asyncio.gather(
            self.vt.lookup_hash(file_hash),
            self.otx.lookup_hash(file_hash),
            self.abusech.lookup_hash(file_hash),
            return_exceptions=True,
        )
        keys = ["virustotal", "otx", "abusech"]
        return {
            k: (v if not isinstance(v, Exception) else {"available": False, "error": str(v)})
            for k, v in zip(keys, results)
        }

    async def _enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Run VT, OTX, AbuseCH, DeepDarkCTI on a domain."""
        results = await asyncio.gather(
            self.vt.lookup_domain(domain),
            self.otx.lookup_domain(domain),
            self.abusech.lookup_ip(domain),       # URLhaus host lookup accepts domain too
            self.deepdarkcti.lookup_domain(domain),
            return_exceptions=True,
        )
        keys = ["virustotal", "otx", "abusech", "deepdarkcti"]
        return {
            k: (v if not isinstance(v, Exception) else {"available": False, "error": str(v)})
            for k, v in zip(keys, results)
        }

    async def _enrich_url(self, url: str) -> Dict[str, Any]:
        """Run AbuseCH URLhaus on a URL."""
        result = await self.abusech.lookup_url(url)
        if isinstance(result, Exception):
            result = {"available": False, "error": str(result)}
        return {"abusech": result}

    # ── Per-indicator scoring ─────────────────────────────────────────────────

    def _summarise_indicator(
        self, value: str, ioc_type: str, provider_data: Dict, ioc_meta: Dict
    ) -> Dict[str, Any]:
        """
        Given raw provider results for one indicator, compute:
          - weighted score with corroboration multiplier + RIOT suppression
          - temporal freshness applied
          - metadata extraction (malware families, categories)
        """
        # Compute per-provider scores
        provider_scores: Dict[str, Optional[float]] = {}
        for provider in SCORE_WEIGHTS:
            pdata = provider_data.get(provider, {})
            if not isinstance(pdata, dict):
                pdata = {}
            score = self._provider_score(provider, pdata, ioc_type)
            provider_scores[provider] = score

        # Weighted average normalized by responding providers
        weighted_sum   = 0.0
        total_weight   = 0.0
        providers_malicious = 0

        riot_suppressed = False
        # Check GreyNoise RIOT before accumulating
        gn_data = provider_data.get("greynoise", {})
        if isinstance(gn_data, dict) and gn_data.get("riot", False):
            riot_suppressed = True

        for provider, weight in SCORE_WEIGHTS.items():
            score = provider_scores.get(provider)
            if score is None:
                continue   # provider unavailable / not applicable
            if score > 0.5:
                providers_malicious += 1
            weighted_sum += score * weight
            total_weight += weight

        raw_score = (weighted_sum / total_weight) if total_weight > 0 else 0.0

        # Corroboration multiplier
        corroboration_multiplier = min(
            CORROBORATION_CAP,
            1.0 + CORROBORATION_PER_PROVIDER * max(0, providers_malicious - 1)
        )
        scored = min(1.0, raw_score * corroboration_multiplier)

        # Temporal freshness — pick most recent last_seen across providers
        last_seen_dates = []
        for pdata in provider_data.values():
            if isinstance(pdata, dict):
                for key in ("last_seen", "last_reported", "last_update"):
                    v = pdata.get(key)
                    if v:
                        last_seen_dates.append(v)
        best_date = max(last_seen_dates) if last_seen_dates else None
        freshness = _freshness_multiplier(best_date)
        scored = min(1.0, scored * freshness)

        # GreyNoise RIOT soft suppressor
        if riot_suppressed:
            scored = scored * 0.15
            logger.debug(f"RIOT suppression applied to {value}: score reduced to {scored:.3f}")

        # Extract metadata
        malware_families = list({
            fam
            for provider, pdata in provider_data.items()
            if isinstance(pdata, dict)
            for fam in (
                pdata.get("malware_families", []) or
                [pdata.get("malware")] if pdata.get("malware") else []
            )
            if fam
        })
        threat_categories = []
        abuseipdb_data = provider_data.get("abuseipdb", {})
        if isinstance(abuseipdb_data, dict):
            threat_categories = abuseipdb_data.get("categories", [])

        return {
            "ioc_type":             ioc_type,
            "role":                 ioc_meta.get("role", "other"),
            "field":                ioc_meta.get("field", ""),
            "providers":            {k: v for k, v in provider_data.items() if isinstance(v, dict)},
            "provider_scores":      {k: round(v, 3) for k, v in provider_scores.items() if v is not None},
            "corroboration_count":  providers_malicious,
            "corroboration_mult":   round(corroboration_multiplier, 3),
            "freshness_mult":       round(freshness, 2),
            "riot_suppressed":      riot_suppressed,
            "indicator_score":      round(scored, 3),
            "is_malicious":         scored >= MALICIOUS_THRESHOLD,
            "malware_families":     malware_families,
            "threat_categories":    threat_categories,
            "last_seen":            best_date,
        }

    def _provider_score(self, provider: str, data: Dict, ioc_type: str) -> Optional[float]:
        """Extract 0.0–1.0 maliciousness score from a single provider result.
        Returns None if provider is unavailable/not applicable for this ioc_type."""
        if not data:
            return None
        if data.get("available") is False:
            return None

        if provider == "virustotal":
            total = data.get("total", 0)
            mal   = data.get("malicious", 0)
            return (mal / total) if total > 0 else 0.0

        elif provider == "abuseipdb":
            if ioc_type != "ip":
                return None   # AbuseIPDB only applicable to IPs
            return data.get("confidence", 0) / 100.0

        elif provider == "otx":
            pulses = data.get("pulse_count", 0)
            return min(pulses / 10.0, 1.0)   # normalize: 10+ pulses = max

        elif provider == "greynoise":
            if ioc_type != "ip":
                return None   # GreyNoise is IP-only
            cls = data.get("classification", "unknown")
            noise = data.get("noise", False)
            if cls == "malicious":
                return 1.0
            elif cls == "benign":
                return 0.05   # not zero — could be proxy abuse
            elif noise:
                return 0.30   # internet background scanner — suspicious
            else:
                return 0.15   # unknown, not scanning

        elif provider == "abusech":
            # Score based on component hits
            is_malicious = data.get("is_malicious", False)
            if not is_malicious:
                return 0.0
            # URL type uses freshness from URLhaus
            url_data = data.get("urlhaus", {})
            if isinstance(url_data, dict) and url_data.get("found"):
                return 1.0
            tf_data = data.get("threatfox", {})
            if isinstance(tf_data, dict) and tf_data.get("found"):
                confidence = tf_data.get("confidence", 50) / 100.0
                return min(1.0, confidence * 1.2)   # ThreatFox confidence directly
            return 0.8 if is_malicious else 0.0

        elif provider == "geoip":
            if ioc_type != "ip":
                return None   # GeoIP is IP-only
            if data.get("private", False):
                return None
            score = 0.0
            if data.get("is_proxy", False):
                score = max(score, 0.65)
            if data.get("is_hosting", False):
                score = max(score, 0.35)
            if data.get("country_code", "") in HIGH_RISK_COUNTRIES:
                score = min(1.0, score + 0.10)
            return score

        elif provider == "deepdarkcti":
            # Binary: found in dark web / ransomware / C2 / phishing feeds
            if not data.get("found", False):
                return 0.0
            matches = data.get("matches", [])
            # Ransomware C2 / C&C = highest severity
            if "ransomware_c2" in matches or "command_and_control" in matches:
                return 1.0
            if "phishing" in matches:
                return 0.80
            return 0.70   # generic dark web presence

        return None

    # ── Alert-level aggregate ─────────────────────────────────────────────────

    def _compute_alert_score(
        self, per_indicator: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        Compute alert-level aggregate score from all indicator scores.

        Strategy:
          1. Weighted-by-role-weight average of indicator scores
          2. + Breadth bonus: +0.05 per indicator scoring > 0.4 (max +0.20)
          3. Capped at 1.0

        Top indicators: sorted by indicator_score descending (top 3).
        """
        if not per_indicator:
            return 0.0, []

        weight_sum = 0.0
        score_sum  = 0.0
        breadth_bonus = 0.0
        scored_indicators = []

        for ioc_value, ind in per_indicator.items():
            iscore = ind.get("indicator_score", 0.0)
            rw     = ind.get("role_weight", 0.7)
            score_sum  += iscore * rw
            weight_sum += rw
            scored_indicators.append((ioc_value, iscore))
            if iscore > 0.4:
                breadth_bonus = min(0.20, breadth_bonus + 0.05)

        base = (score_sum / weight_sum) if weight_sum > 0 else 0.0
        aggregate = min(1.0, base + breadth_bonus)

        top = sorted(scored_indicators, key=lambda x: x[1], reverse=True)[:3]
        top_indicators = [v for v, _ in top if _ > 0]

        return aggregate, top_indicators

    # ── Result helpers ────────────────────────────────────────────────────────

    def _primary_geo(
        self, ips: List[Dict], per_indicator: Dict
    ) -> Dict[str, Any]:
        """Return GeoIP data for the highest-scoring src IP."""
        src_ips = [i for i in ips if i.get("role") == "src"]
        candidates = src_ips or ips
        for ioc in candidates:
            ind = per_indicator.get(ioc["value"], {})
            providers = ind.get("providers", {})
            geo = providers.get("geoip", {})
            if isinstance(geo, dict) and geo.get("country"):
                return {
                    "ip": ioc["value"],
                    "country": geo.get("country", ""),
                    "country_code": geo.get("country_code", ""),
                    "city": geo.get("city", ""),
                    "asn": geo.get("asn", ""),
                    "isp": geo.get("isp", ""),
                    "is_proxy": geo.get("is_proxy", False),
                    "is_hosting": geo.get("is_hosting", False),
                }
        return {}

    def _primary_infra(
        self, ips: List[Dict], per_indicator: Dict
    ) -> Dict[str, Any]:
        """Return infrastructure intelligence from GeoIP/GreyNoise for the highest-scoring IP."""
        for ioc in ips:
            ind = per_indicator.get(ioc["value"], {})
            providers = ind.get("providers", {})
            geo = providers.get("geoip", {})
            gn  = providers.get("greynoise", {})
            if isinstance(geo, dict) and geo.get("available"):
                return {
                    "ip": ioc["value"],
                    "isp": geo.get("isp", ""),
                    "asn": geo.get("asn", ""),
                    "is_proxy": geo.get("is_proxy", False),
                    "is_hosting": geo.get("is_hosting", False),
                    "greynoise_classification": gn.get("classification", "unknown") if isinstance(gn, dict) else "unknown",
                    "greynoise_noise": gn.get("noise", False) if isinstance(gn, dict) else False,
                }
        return {}


# ── Singleton ─────────────────────────────────────────────────────────────────

_ti_service: Optional[ThreatIntelService] = None


def get_threat_intel_service() -> ThreatIntelService:
    global _ti_service
    if _ti_service is None:
        _ti_service = ThreatIntelService()
    return _ti_service
