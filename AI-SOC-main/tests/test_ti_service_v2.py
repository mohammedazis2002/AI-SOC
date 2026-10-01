#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, io
try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
except Exception:
    pass
"""
Threat Intelligence Service v2 — Test Script
=============================================
Tests against real examples from synthetic_wazuh_alerts.json.

Selected test cases cover:
  1. Data exfiltration   — dst IP should score high (exfil role)
  2. Malware with hash   — hash + src IP enrichment
  3. C2 network traffic  — dst IP as C2 beacon
  4. Brute-force auth    — src IP as attacker
  5. Credential dumping  — hash + IP + chain alert

Run: python test_ti_service.py
     (requires: pip install aiohttp; API keys in .env or environment)
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, List

# ── Path fix — ensure backend is importable ───────────────────────────────────
SOAR_ROOT = Path(__file__).parent
sys.path.insert(0, str(SOAR_ROOT / "backend"))

# Load .env if present
env_file = SOAR_ROOT / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))

from services.enrichment.threat_intel_service import ThreatIntelService, _extract_indicators

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED   = "\033[91m"
GRN   = "\033[92m"
YEL   = "\033[93m"
BLU   = "\033[94m"
MAG   = "\033[95m"
CYN   = "\033[96m"
WHT   = "\033[97m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RST   = "\033[0m"

BAR   = "=" * 74


def col(text: str, colour: str) -> str:
    return f"{colour}{text}{RST}"


def print_banner(title: str):
    print(f"\n{col(BAR, BLU)}")
    print(f"{col(f'  {title}', BOLD + WHT)}")
    print(f"{col(BAR, BLU)}")


def print_section(title: str):
    print(f"\n  {col('>> ' + title, YEL)}")


def score_bar(score: float, width: int = 30) -> str:
    filled = int(score * width)
    bar = "#" * filled + "-" * (width - filled)
    if score >= 0.7:
        colour = RED
    elif score >= 0.4:
        colour = YEL
    else:
        colour = GRN
    return f"{colour}{bar}{RST}  {col(f'{score:.3f}', BOLD)}"


def fmt_indicator(ioc_value: str, summary: Dict) -> str:
    role  = summary.get("role", "?")
    itype = summary.get("ioc_type", "?")
    score = summary.get("indicator_score", 0.0)
    corr  = summary.get("corroboration_count", 0)
    riot  = " [RIOT]" if summary.get("riot_suppressed") else ""
    fresh = summary.get("freshness_mult", 1.0)
    rw    = summary.get("role_weight", 0.0)
    mal   = col("MALICIOUS", RED) if summary.get("is_malicious") else col("clean", GRN)

    lines = [
        f"    {col(ioc_value, BOLD + CYN)}  [{itype}] role={role}(×{rw:.1f}){riot}",
        f"    score: {score_bar(score)}  {mal}",
        f"    corroboration: {corr} providers agree  |  freshness×{fresh:.2f}",
    ]

    # Provider breakdown
    ps = summary.get("provider_scores", {})
    if ps:
        pline = "    providers: " + "  ".join(
            f"{k}={col(f'{v:.2f}', RED if v >= 0.4 else GRN)}"
            for k, v in ps.items()
        )
        lines.append(pline)

    fam = summary.get("malware_families", [])
    if fam:
        lines.append(f"    {col('malware: ' + ', '.join(fam[:5]), MAG)}")

    cats = summary.get("threat_categories", [])
    if cats:
        lines.append(f"    categories: {', '.join(cats[:5])}")

    return "\n".join(lines)


def print_result(case_name: str, alert: Dict, result: Dict, elapsed: float):
    print_banner(case_name)

    # Indicators extracted
    inds = result.get("indicators", {})
    print_section("Extracted Indicators")
    for itype in ("ips", "hashes", "domains", "urls"):
        items = inds.get(itype, [])
        if items:
            print(f"    {itype.upper()}: " + ", ".join(
                f"{col(i['value'], CYN)}({i['role']})" for i in items
            ))

    print_section("Per-Indicator Enrichment")
    per = result.get("per_indicator", {})
    for ioc_value, summary in per.items():
        print(fmt_indicator(ioc_value, summary))
        print()

    # Alert-level summary
    print_section("Alert Aggregate")
    agg  = result.get("aggregate_score", 0.0)
    mal  = result.get("is_malicious", False)
    cooc = "YES" if result.get("co_occurrence_amplified") else "no"
    print(f"    Aggregate Score:  {score_bar(agg)}")
    print(f"    Is Malicious:     {col('YES [!]', RED + BOLD) if mal else col('NO [OK]', GRN + BOLD)}")
    print(f"    Malicious IOCs:   {result.get('malicious_indicator_count', 0)}")
    print(f"    Co-occurrence:    {col(cooc, MAG if cooc == 'YES' else DIM)}")

    top = result.get("top_threat_indicators", [])
    if top:
        print(f"    Top Threats:      {col(', '.join(top), RED)}")

    fam = result.get("malware_families", [])
    if fam:
        print(f"    Malware Families: {col(', '.join(fam[:5]), MAG)}")

    cats = result.get("threat_categories", [])
    if cats:
        print(f"    Threat Categories:{', '.join(cats[:5])}")

    geo = result.get("geolocation_summary", {})
    if geo:
        proxy = " [PROXY]" if geo.get("is_proxy") else ""
        host  = " [HOSTING]" if geo.get("is_hosting") else ""
        print(f"    Geo (primary src):{geo.get('country','')} / {geo.get('city','')} / {geo.get('isp','')}{proxy}{host}")

    infra = result.get("infrastructure_summary", {})
    if infra:
        ports = infra.get("open_ports", [])
        vulns = infra.get("vulns", [])
        print(f"    Shodan:           ports={ports[:5]}  CVEs={vulns[:3]}")

    print(f"\n    {col(f'Enrichment time: {elapsed:.2f}s', DIM)}")


# ── Test alert selection ──────────────────────────────────────────────────────

def pick_test_alerts():
    """
    Pick specific alert types from synthetic_wazuh_alerts.json.
    Selects one of each interesting category.
    """
    alerts_path = SOAR_ROOT / "Attack_Data_Syn" / "synthetic_wazuh_alerts.json"
    if not alerts_path.exists():
        print(f"  {col('WARN: synthetic_wazuh_alerts.json not found', YEL)}")
        return _fallback_alerts()

    print(f"Loading alerts from: {alerts_path}")
    with open(alerts_path, "r") as f:
        all_alerts = json.load(f)

    # Categories we want
    targets = {
        "data_exfiltration": None,
        "malware":           None,
        "command_and_control": None,
        "authentication":    None,
        "zero_day":          None,
        "web":               None,
    }
    # Prefer alerts with a public (non-RFC1918) srcip or a hash
    selected = []
    found = set()

    for alert in all_alerts:
        groups  = alert.get("rule", {}).get("groups", [])
        data    = alert.get("data", {})
        has_pub_ip = any(
            ip and not ip.startswith("10.") and not ip.startswith("192.168.")
            and not ip.startswith("172.")
            for ip in [data.get("srcip"), data.get("dstip")]
            if ip
        )
        has_hash = bool(data.get("md5") or data.get("sha256"))

        for g in groups:
            if g in targets and g not in found:
                if has_pub_ip or has_hash or g in ("authentication", "web"):
                    targets[g] = alert
                    found.add(g)

        if len(found) == len(targets):
            break

    for g, alert in targets.items():
        if alert:
            selected.append((g, alert))

    if not selected:
        return _fallback_alerts()
    return selected


def _fallback_alerts():
    """
    Hardcoded fallback using real-looking synthetic entries
    so the test runs even without the JSON file.
    """
    return [
        ("malware_with_hash", {
            "id": "27154",
            "rule": {"level": 15, "description": "Unpatched vulnerability exploit",
                     "groups": ["malware", "impact"],
                     "mitre": {"id": ["T1055"], "tactic": ["Impact"], "technique": ["Process Injection"]}},
            "agent": {"name": "DC-04", "ip": "10.24.187.56"},
            "data": {
                "srcip": "203.193.32.244",   # public
                "dstip": "10.24.187.56",
                "md5":    "f89f55eb502b40798a1d0e47fe087ed5",
                "sha256": "4bf92cb514244926b9c0fb5cfb2ecde7f66880bf54824b60a44b917c7213570a",
                "process": "sc.exe",
                "file": "C:\\Windows\\System32\\file_1812.exe",
            },
        }),
        ("data_exfiltration", {
            "id": "10642",
            "rule": {"level": 9, "description": "Cloud storage upload detected",
                     "groups": ["data_exfiltration", "defense_evasion"],
                     "mitre": {"id": ["T1537"], "tactic": ["Exfiltration"], "technique": ["Cloud storage"]}},
            "agent": {"name": "LB-03", "ip": "10.135.184.29"},
            "data": {
                "srcip": "10.135.184.29",    # internal src
                "dstip": "203.193.32.244",   # public dst — the exfil target
            },
        }),
        ("c2_beacon", {
            "id": "12763",
            "rule": {"level": 14, "description": "C2 beacon detected",
                     "groups": ["command_and_control", "network"],
                     "mitre": {"id": ["T1071"], "tactic": ["Command and Control"], "technique": ["Application Layer Protocol"]}},
            "agent": {"name": "WORKSTATION-051", "ip": "10.121.144.67"},
            "data": {
                "srcip": "10.121.144.67",
                "dstip": "185.191.175.9",    # public dst = C2 server
                "dstport": 443,
                "protocol": "TCP",
            },
        }),
        ("brute_force_auth", {
            "id": "23710",
            "rule": {"level": 5, "description": "Failed login attempts",
                     "groups": ["authentication", "exfiltration"],
                     "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}},
            "agent": {"name": "WORKSTATION-040", "ip": "10.204.217.208"},
            "data": {
                "srcip": "185.191.175.9",    # public src = brute forcing attacker
                "dstip": "10.204.217.208",
                "dstport": 3306,
                "authentication": {"success": "no", "attempts": 3},
            },
        }),
    ]


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    print(f"\n{col(BAR, MAG)}")
    print(f"{col('  THREAT INTELLIGENCE SERVICE v2 - Test Run', BOLD + WHT)}")
    print(f"{col('  Corroboration | Role-Aware | Temporal | RIOT | Co-occurrence', DIM)}")
    print(f"{col(BAR, MAG)}")

    # Check env keys
    keys_present = []
    keys_missing  = []
    for var in ("VIRUSTOTAL_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY",
                "GREYNOISE_API_KEY", "SHODAN_API_KEY"):
        if os.environ.get(var):
            keys_present.append(var.replace("_API_KEY", ""))
        else:
            keys_missing.append(var.replace("_API_KEY", ""))
    print(f"\n  API keys present: {col(', '.join(keys_present) or 'none', GRN)}")
    if keys_missing:
        print(f"  API keys missing: {col(', '.join(keys_missing), YEL)} (providers will return no-key stub)")
    print(f"  GeoIP / AbuseCH: free, no key required")

    # Quick indicator extraction sanity test (no network)
    print(f"\n{col('  >> Indicator extraction test (no network)...', CYN)}")
    test_alert = {
        "rule": {"groups": ["data_exfiltration"]},
        "data": {
            "srcip": "10.0.0.1",
            "dstip": "203.193.32.244",
            "md5": "f89f55eb502b40798a1d0e47fe087ed5",
            "sha256": "4bf92cb514244926b9c0fb5cfb2ecde7f66880bf54824b60a44b917c7213570a",
            "url": "http://evil.example.com/upload?data=secret",
        }
    }
    inds = _extract_indicators(test_alert)
    print(f"  IPs:    {[i['value'] for i in inds['ips']]}")
    print(f"  Hashes: {[i['value'][:12]+'...' for i in inds['hashes']]}")
    print(f"  URLs:   {[i['value'] for i in inds['urls']]}")
    print(f"  Domains:{[i['value'] for i in inds['domains']]}")

    # Real enrichment tests
    service = ThreatIntelService()
    test_cases = pick_test_alerts()

    print(f"\n  Running {len(test_cases)} enrichment test(s) against live APIs...")
    print(f"  {col('(providers without API keys will return available:False)', DIM)}")

    for case_name, alert in test_cases:
        t0 = time.time()
        result = await service.enrich_alert(dict(alert))
        elapsed = time.time() - t0
        ti_result = result.get("enrichments", {}).get("threat_intel", result)
        print_result(case_name.replace("_", " ").title(), alert, ti_result, elapsed)

    print(f"\n{col(BAR, MAG)}")
    print(f"{col('  Test run complete.', BOLD + GRN)}")
    print(f"{col(BAR, MAG)}")


if __name__ == "__main__":
    asyncio.run(main())
