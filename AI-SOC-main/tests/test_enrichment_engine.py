"""
Enrichment Engine — End-to-End Test Script
===========================================
Tests all components of the new enrichment engine:
  1. MITRE 3-layer semantic pipeline (requires Qdrant + indexed MITRE data)
  2. All 9 TI providers (requires API keys in .env)

Run from project root:
    python test_enrichment_engine.py

Flags:
    --mitre-only     Only test MITRE enrichment
    --ti-only        Only test TI providers
    --ip <IP>        Test a specific IP (default: 185.220.101.1 — known Tor exit)
    --hash <HASH>    Test a specific file hash
"""

import asyncio
import sys
import json
import logging
import argparse
from datetime import datetime
from pathlib import Path

# Load .env before anything else
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("enrichment_test")

# ── Test Alerts ──────────────────────────────────────────────────────────────

SAMPLE_ALERTS = [
    {
        "name": "Brute Force SSH (Layer 1 — explicit MITRE ID)",
        "alert": {
            "alert_id": "test_001",
            "finding": {
                "title": "Multiple failed SSH login attempts",
                "desc": "Brute force attack detected against SSH service. 500 failed attempts in 60 seconds.",
            },
            "rule": {
                "description": "SSH brute force attack",
                "mitre": {"id": "T1110", "technique": "Brute Force"},
            },
            "src_endpoint": {"ip": "185.220.101.1"},
            "dst_endpoint": {"ip": "10.0.0.5"},
            "severity_id": 4,
        }
    },
    {
        "name": "PowerShell Execution (Layer 3 — no MITRE ID, semantic only)",
        "alert": {
            "alert_id": "test_002",
            "finding": {
                "title": "Suspicious PowerShell execution",
                "desc": "PowerShell launched with encoded command and bypass execution policy.",
            },
            "process": {
                "name": "powershell.exe",
                "cmd_line": "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAA= -ExecutionPolicy Bypass -NoProfile",
            },
            "src_endpoint": {"ip": "192.168.1.100"},
            "severity_id": 3,
        }
    },
    {
        "name": "Credential Dumping (Layer 3 — semantic)",
        "alert": {
            "alert_id": "test_003",
            "finding": {
                "title": "LSASS memory access detected",
                "desc": "Process accessed LSASS memory, possible credential dumping attempt.",
            },
            "process": {
                "name": "mimikatz.exe",
                "cmd_line": "mimikatz.exe sekurlsa::logonpasswords",
            },
            "src_endpoint": {"ip": "10.0.0.50"},
            "severity_id": 5,
        }
    },
    {
        "name": "Ransomware File Encryption (Layer 3 — semantic)",
        "alert": {
            "alert_id": "test_004",
            "finding": {
                "title": "Mass file encryption detected",
                "desc": "High volume of file rename operations with .locked extension. Possible ransomware activity.",
            },
            "file": {
                "path": "C:\\Users\\victim\\Documents\\report.docx.locked",
                "hashes": {
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            },
            "src_endpoint": {"ip": "10.0.0.75"},
            "severity_id": 5,
        }
    },
]


# ── MITRE Tests ──────────────────────────────────────────────────────────────

def test_mitre_enrichment():
    """Test the 3-layer MITRE enrichment pipeline."""
    print("\n" + "="*70)
    print("MITRE ATT&CK ENRICHMENT — 3-LAYER PIPELINE")
    print("="*70)

    try:
        from backend.services.enrichment.mitre_enrichment_service import MITREEnrichmentService
        service = MITREEnrichmentService()
    except Exception as e:
        print(f"❌ Failed to initialize MITREEnrichmentService: {e}")
        print("   → Make sure Qdrant is running and MITRE data is indexed.")
        print("   → Run: python scripts/setup/index_mitre_to_qdrant.py")
        return False

    all_passed = True
    for test in SAMPLE_ALERTS:
        print(f"\n📋 Test: {test['name']}")
        alert = dict(test["alert"])
        try:
            service.enrich(alert)
            mitre = alert.get("enrichments", {}).get("mitre", {})

            tech_id = mitre.get("technique_id")
            tech_name = mitre.get("technique_name")
            sub_id = mitre.get("subtechnique_id")
            sub_name = mitre.get("subtechnique_name")
            method = mitre.get("mapping_method")
            conf = mitre.get("technique_confidence", 0)
            tactic = mitre.get("tactic_name")

            print(f"   Tactic:       {tactic}")
            print(f"   Technique:    {tech_id} — {tech_name} (conf={conf:.2f})")
            if sub_id:
                print(f"   Sub-technique:{sub_id} — {sub_name} (conf={mitre.get('subtechnique_confidence', 0):.2f})")
            print(f"   Method:       {method}")
            print(f"   Review needed:{mitre.get('analyst_review_required')}")

            if tech_id:
                print(f"   ✅ PASS")
            else:
                print(f"   ⚠️  No technique found (may need Qdrant data indexed)")
                all_passed = False

        except Exception as e:
            print(f"   ❌ ERROR: {e}")
            all_passed = False

    return all_passed


# ── TI Tests ─────────────────────────────────────────────────────────────────

async def test_ti_providers(test_ip: str, test_hash: str):
    """Test all TI providers with a known malicious IP."""
    print("\n" + "="*70)
    print("THREAT INTELLIGENCE PROVIDERS")
    print("="*70)
    print(f"Test IP:   {test_ip}")
    print(f"Test Hash: {test_hash}")

    try:
        from backend.services.enrichment.threat_intel_service import ThreatIntelService
        service = ThreatIntelService()
    except Exception as e:
        print(f"❌ Failed to initialize ThreatIntelService: {e}")
        return False

    # Build a test alert with the IP and hash
    test_alert = {
        "alert_id": "ti_test_001",
        "finding": {"title": "TI Provider Test"},
        "src_endpoint": {"ip": test_ip},
        "file": {"hashes": {"sha256": test_hash}},
    }

    print("\nRunning all providers in parallel...")
    start = datetime.now()
    await service.enrich_alert(test_alert)
    elapsed = (datetime.now() - start).total_seconds()

    ti = test_alert.get("enrichments", {}).get("threat_intel", {})

    print(f"\n⏱️  Total time: {elapsed:.2f}s")
    print(f"\n{'Provider':<20} {'Status':<12} {'Malicious':<12} {'Key Info'}")
    print("-" * 70)

    providers = [
        ("virustotal",  "malicious",       None),
        ("otx",         "pulse_count",     None),
        ("abuseipdb",   "confidence",      None),
        ("geoip",       "country",         None),
        ("abusech",     "is_malicious",    None),
        ("greynoise",   "classification",  None),
    ]

    # provider_data is keyed by IOC value (IP or hash), then by provider name.
    # per_indicator holds computed summaries (score, is_malicious, etc.)
    provider_data = ti.get("provider_data", {})
    ip_providers   = provider_data.get(test_ip, {})
    hash_providers = provider_data.get(test_hash, {})

    all_passed = True
    for provider, key1, _ in providers:
        # IP lookup takes priority; fall back to hash lookup (VT/OTX/AbuseCH check both)
        data = ip_providers.get(provider) or hash_providers.get(provider) or {}
        if not data:
            status = "❌ MISSING"
            all_passed = False
        elif data.get("skipped"):
            status = "⏭️  SKIPPED"
        elif not data.get("available", True):
            # UNAVAIL = provider responded but had no data (e.g. timeout/no match)
            # This is a soft failure — network issue, not a code bug
            status = "⚠️  UNAVAIL"
        else:
            status = "✅ OK"

        is_mal   = data.get("is_malicious", False)
        val1     = data.get(key1, "—")
        key_info = f"{key1}={val1}"

        print(f"  {provider:<18} {status:<12} {'YES' if is_mal else 'no':<12} {key_info}")

    print("\n" + "-" * 70)
    print(f"Aggregate Score: {ti.get('aggregate_score', 0):.3f}")
    print(f"Is Malicious:    {ti.get('is_malicious', False)}")

    # Per-indicator score breakdown
    per_ind = ti.get("per_indicator", {})
    if per_ind:
        print("\nPer-indicator breakdown:")
        for ioc_val, ioc_data in per_ind.items():
            score  = ioc_data.get("indicator_score", 0)
            mal    = ioc_data.get("is_malicious", False)
            itype  = ioc_data.get("ioc_type", "?")
            pscores = ioc_data.get("provider_scores", {})
            ps_str = "  ".join(f"{p}={v:.2f}" for p, v in pscores.items() if v is not None)
            print(f"  [{itype}] {ioc_val[:38]:<40} score={score:.3f}  mal={'YES' if mal else 'no'}  |  {ps_str}")

    return all_passed




# ── Full Pipeline Test ────────────────────────────────────────────────────────

async def test_full_pipeline():
    """Test MITRE + TI together through alert_pipeline.py."""
    print("\n" + "="*70)
    print("FULL PIPELINE TEST (alert_pipeline.py)")
    print("="*70)

    try:
        from backend.services.ingestion.alert_pipeline import AlertProcessor
        processor = AlertProcessor()
    except Exception as e:
        print(f"❌ Failed to initialize AlertProcessor: {e}")
        return False

    alert = {
        "alert_id": "pipeline_test_001",
        "finding": {
            "title": "SSH Brute Force from known malicious IP",
            "desc": "Multiple failed SSH authentication attempts from external IP.",
        },
        "rule": {"description": "SSH brute force attack", "mitre": {"id": "T1110"}},
        "src_endpoint": {"ip": "185.220.101.1"},
        "dst_endpoint": {"ip": "10.0.0.5"},
        "severity_id": 4,
        "class_uid": 4001,
    }

    try:
        result = await processor.process_alert(alert)
        print(f"\n✅ Pipeline completed")
        print(f"   Queue:        {result.get('queue_assignment')}")
        print(f"   MITRE:        {result.get('enrichments', {}).get('mitre', {}).get('technique_id')}")
        print(f"   TI Score:     {result.get('enrichments', {}).get('threat_intel', {}).get('aggregate_score', 0):.3f}")
        print(f"   FP Score:     {result.get('fp_analysis', {}).get('fp_score', 0):.2f}")
        return True
    except Exception as e:
        print(f"❌ Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return False


# ── Main ─────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Test SOAR Enrichment Engine")
    parser.add_argument("--mitre-only", action="store_true", help="Only test MITRE")
    parser.add_argument("--ti-only", action="store_true", help="Only test TI providers")
    parser.add_argument("--pipeline", action="store_true", help="Test full pipeline")
    parser.add_argument("--ip", default="185.220.101.1", help="IP to test (default: known Tor exit)")
    parser.add_argument("--hash", default="44d88612fea8a8f36de82e1278abb02f", help="Hash to test")
    args = parser.parse_args()

    print("\n" + "🔍 " * 20)
    print("SOAR ENRICHMENT ENGINE — TEST SUITE")
    print("🔍 " * 20)

    results = {}

    if not args.ti_only:
        results["mitre"] = test_mitre_enrichment()

    if not args.mitre_only:
        results["ti"] = await test_ti_providers(args.ip, args.hash)

    if args.pipeline:
        results["pipeline"] = await test_full_pipeline()

    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    for name, passed in results.items():
        icon = "✅" if passed else "❌"
        print(f"  {icon} {name.upper()}")

    all_ok = all(results.values())
    print("\n" + ("✅ ALL TESTS PASSED" if all_ok else "⚠️  SOME TESTS FAILED"))
    print("="*70 + "\n")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
