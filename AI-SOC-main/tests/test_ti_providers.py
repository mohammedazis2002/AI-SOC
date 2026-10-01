"""
Threat Intel Provider Live Test (ASCII-safe)
=============================================
Tests all TI providers against a dummy alert with known-bad IOCs.
Run from soar-platform directory:
    python test_ti_providers.py
"""
import asyncio
import logging
import sys
import os
from pathlib import Path

ROOT = Path(r"C:\Users\Shruthi Kannan\Documents\SOAR\soar-platform")
sys.path.insert(0, str(ROOT))

logging.basicConfig(level=logging.WARNING, format="%(name)s [%(levelname)s] %(message)s")

# Known-bad IOCs for testing
TEST_IP    = "198.235.24.130"   # high AbuseIPDB score (known spam source)
TEST_IP2   = "45.33.32.156"    # scanme.nmap.org — likely noise/benign in GN
TEST_HASH  = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # EICAR SHA256
TEST_DOMAIN = "malware.wicar.org"

DUMMY_ALERT = {
    "alert_id": "test-ti-001",
    "rule": {"level": 10, "groups": ["malware", "command_and_control"]},
    "data": {"srcip": TEST_IP, "dstip": TEST_IP2, "sha256": TEST_HASH},
    "network_activity": {"domain": TEST_DOMAIN, "remote_ip": "91.92.109.199"},
    "finding": {"title": "Suspicious C2 connection"},
}


def short(data: dict) -> str:
    if not data:
        return "None"
    if data.get("available") is False:
        return "[UNAVAIL] " + data.get("error", data.get("reason", "no key?"))
    parts = []
    if "malicious" in data and "total" in data:
        parts.append(f"mal={data['malicious']}/{data['total']}")
    if "confidence" in data:
        parts.append(f"abipdb={data['confidence']}%")
    if "pulse_count" in data:
        parts.append(f"pulses={data['pulse_count']}")
    if "classification" in data:
        cls = data["classification"]
        parts.append(f"gn={cls}")
        if data.get("noise"):
            parts.append("noise=T")
        if data.get("riot"):
            parts.append("RIOT=T")
    if "country" in data and data.get("country"):
        parts.append(f"geo={data['country']}")
    if "is_proxy" in data:
        parts.append(f"proxy={data['is_proxy']}")
    if "isp" in data and data.get("isp"):
        parts.append(f"isp={data['isp'][:20]}")
    if data.get("is_malicious"):
        parts.append("**MALICIOUS**")
    if "found" in data:
        parts.append(f"found={data['found']}")
    if not parts:
        return "ok (no signals)"
    return "  ".join(parts)


async def run(name, coro):
    try:
        r = await asyncio.wait_for(coro, timeout=20)
        return r
    except asyncio.TimeoutError:
        return {"available": False, "error": "timeout"}
    except Exception as e:
        return {"available": False, "error": str(e)}


async def main():
    from backend.services.enrichment.providers.virustotal  import VirusTotalProvider
    from backend.services.enrichment.providers.otx         import OTXProvider
    from backend.services.enrichment.providers.abuseipdb   import AbuseIPDBProvider
    from backend.services.enrichment.providers.geoip       import GeoIPProvider
    from backend.services.enrichment.providers.abusech     import AbuseCHProvider
    from backend.services.enrichment.providers.greynoise   import GreyNoiseProvider
    from backend.services.enrichment.providers.misp        import MISPProvider
    from backend.services.enrichment.providers.deepdarkcti import DeepDarkCTIProvider
    from backend.services.enrichment.providers.shodan      import ShodanProvider

    vt        = VirusTotalProvider()
    otx       = OTXProvider()
    abuseipdb = AbuseIPDBProvider()
    geoip     = GeoIPProvider()
    abusech   = AbuseCHProvider()
    greynoise = GreyNoiseProvider()
    misp      = MISPProvider()
    deepdark  = DeepDarkCTIProvider()
    shodan    = ShodanProvider()

    # --- Key status ---
    print()
    print("=" * 65)
    print("TI PROVIDER KEY STATUS")
    print("=" * 65)

    keys = {
        "VirusTotal"        : os.getenv("VIRUSTOTAL_API_KEY"),
        "OTX"               : os.getenv("OTX_API_KEY"),
        "AbuseIPDB"         : os.getenv("ABUSEIPDB_API_KEY"),
        "GeoIP"             : "FREE - no key",
        "Abuse.ch ThreatFox": os.getenv("THREATFOX_API_KEY") or os.getenv("ABUSECH_API_KEY"),
        "Abuse.ch URLhaus"  : os.getenv("URLHAUS_API_KEY")   or os.getenv("ABUSECH_API_KEY"),
        "Abuse.ch MBazaar"  : os.getenv("MALWAREBAZAAR_API_KEY") or os.getenv("ABUSECH_API_KEY"),
        "GreyNoise"         : os.getenv("GREYNOISE_API_KEY") or "Community (free, no key)",
        "MISP"              : f"URL={os.getenv('MISP_URL','NOT SET')}  key={'SET' if os.getenv('MISP_API_KEY') else 'NOT SET'}",
        "DeepDarkCTI"       : "FREE - GitHub IOC feeds",
        "Shodan"            : os.getenv("SHODAN_API_KEY") or "NOT SET (free tier = 403)",
    }

    for name, val in keys.items():
        status = "[SET] " if (val and val not in ("NOT SET (free tier = 403)",)) else "[MISS]"
        masked = (val[:8] + "...") if val and len(val) > 12 else (val or "NOT SET")
        print(f"  {status} {name:<25} {masked}")

    # --- IP lookup ---
    print()
    print("=" * 65)
    print(f"IP LOOKUP: {TEST_IP}  (known spam source)")
    print("=" * 65)

    r_vt,  r_otx, r_ab, r_geo, r_abch, r_gn, r_misp, r_dark, r_shodan = await asyncio.gather(
        run("vt",       vt.lookup_ip(TEST_IP)),
        run("otx",      otx.lookup_ip(TEST_IP)),
        run("abuseipdb",abuseipdb.lookup_ip(TEST_IP)),
        run("geoip",    geoip.lookup_ip(TEST_IP)),
        run("abusech",  abusech.lookup_ip(TEST_IP)),
        run("greynoise",greynoise.lookup_ip(TEST_IP)),
        run("misp",     misp.lookup_ip(TEST_IP)),
        run("deepdark", deepdark.lookup_ip(TEST_IP)),
        run("shodan",   shodan.lookup_ip(TEST_IP)),
    )

    print(f"  [ACTIVE]   VirusTotal   {short(r_vt)}")
    print(f"  [ACTIVE]   OTX          {short(r_otx)}")
    print(f"  [ACTIVE]   AbuseIPDB    {short(r_ab)}")
    print(f"  [ACTIVE]   GeoIP        {short(r_geo)}")
    print(f"  [ACTIVE]   Abuse.ch     {short(r_abch)}")
    print(f"  [ACTIVE]   GreyNoise    {short(r_gn)}")
    print(f"  [DEFERRED] MISP         {short(r_misp)}")
    print(f"  [DEFERRED] DeepDarkCTI  {short(r_dark)}")
    print(f"  [DEFERRED] Shodan       {short(r_shodan)}")

    # --- Hash lookup ---
    print()
    print("=" * 65)
    print(f"HASH LOOKUP: {TEST_HASH[:20]}...  (EICAR SHA256)")
    print("=" * 65)

    h_vt, h_otx, h_abch = await asyncio.gather(
        run("vt",    vt.lookup_hash(TEST_HASH)),
        run("otx",   otx.lookup_hash(TEST_HASH)),
        run("abusech",abusech.lookup_hash(TEST_HASH)),
    )
    print(f"  [ACTIVE] VirusTotal  {short(h_vt)}")
    print(f"  [ACTIVE] OTX         {short(h_otx)}")
    print(f"  [ACTIVE] Abuse.ch    {short(h_abch)}")

    # --- Domain lookup ---
    print()
    print("=" * 65)
    print(f"DOMAIN LOOKUP: {TEST_DOMAIN}")
    print("=" * 65)

    d_vt, d_otx, d_dark = await asyncio.gather(
        run("vt",       vt.lookup_domain(TEST_DOMAIN)),
        run("otx",      otx.lookup_domain(TEST_DOMAIN)),
        run("deepdark", deepdark.lookup_domain(TEST_DOMAIN)),
    )
    print(f"  [ACTIVE]   VirusTotal  {short(d_vt)}")
    print(f"  [ACTIVE]   OTX         {short(d_otx)}")
    print(f"  [DEFERRED] DeepDarkCTI {short(d_dark)}")

    # --- Full service ---
    print()
    print("=" * 65)
    print("FULL ThreatIntelService.enrich_alert() ON DUMMY ALERT")
    print("=" * 65)

    import copy
    from backend.services.enrichment.threat_intel_service import ThreatIntelService
    ti = ThreatIntelService()
    alert_copy = copy.deepcopy(DUMMY_ALERT)
    await ti.enrich_alert(alert_copy)
    ti_r = alert_copy.get("enrichments", {}).get("threat_intel", {})

    avail = ti_r.get("available", False)
    print(f"  Available            : {avail}")
    if not avail:
        print(f"  Reason               : {ti_r.get('reason', ti_r.get('error', '?'))}")
    else:
        print(f"  Aggregate score      : {ti_r.get('aggregate_score', 0):.3f}")
        print(f"  Is malicious         : {ti_r.get('is_malicious', False)}")
        print(f"  Malicious indicators : {ti_r.get('malicious_indicator_count', 0)}")
        print(f"  Co-occurrence amp    : {ti_r.get('co_occurrence_amplified', False)}")
        print(f"  Malware families     : {ti_r.get('malware_families', [])}")
        print(f"  Threat categories    : {ti_r.get('threat_categories', [])}")
        geo = ti_r.get("geolocation_summary", {})
        if geo:
            print(f"  Geo (primary src)    : {geo.get('country','')} / {geo.get('isp','')} / proxy={geo.get('is_proxy')}")

        per = ti_r.get("per_indicator", {})
        if per:
            print(f"\n  Per-indicator ({len(per)} total):")
            for ioc, ind in per.items():
                flag = "[MAL]" if ind.get("is_malicious") else "[OK ]"
                print(f"    {flag} {ioc:<30} score={ind.get('indicator_score',0):.3f}  corr={ind.get('corroboration_count',0)}")

    print()
    print("=" * 65)
    print("SUMMARY")
    print("=" * 65)
    print("""
  ACTIVE in ThreatIntelService (wired, scored, in aggregate):
    [OK] VirusTotal     w=0.28  needs VIRUSTOTAL_API_KEY
    [OK] OTX            w=0.16  needs OTX_API_KEY
    [OK] AbuseIPDB      w=0.20  needs ABUSEIPDB_API_KEY
    [OK] GeoIP          w=0.04  FREE (ip-api.com, no key)
    [OK] Abuse.ch       w=0.17  needs THREATFOX_API_KEY (free at auth.abuse.ch)
    [OK] GreyNoise      w=0.15  Community API free; GREYNOISE_API_KEY for full

  DEFERRED (code implemented, NOT wired into ThreatIntelService):
    [--] MISP           Self-hosted instance required (MISP_URL + MISP_API_KEY)
    [--] DeepDarkCTI    FREE, no key -- GitHub IOC feeds for dark web C2
    [--] Shodan         Paid tier required (free = HTTP 403 on /shodan/host/)

  NOT YET IMPLEMENTED:
    [xx] OpenCTI        Listed in original plan as future provider
""")


if __name__ == "__main__":
    asyncio.run(main())