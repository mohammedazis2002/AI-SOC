#!/usr/bin/env python3
"""
Merge all framework-specific compliance JSON files into a single
compliance_rules_full.json and load it into MongoDB.

Run from: soar-platform/backend/data/
Usage: python merge_compliance_rules.py [--load-mongo]
"""

import json
import os
import sys
from pathlib import Path

# ============================================================
# CANONICAL FRAMEWORK FILES — exact control IDs from standards
# One file per framework, supersedes old base+ext pairs
# ============================================================
FRAMEWORK_FILES = [
    "compliance_pci_dss_canonical.json",    # PCI-DSS v4 (35 rules, IDs: 10.2.1 – 2.3.2)
    "compliance_iso27001_canonical.json",   # ISO 27001:2022 (32 rules, IDs: A.5.24 – A.8.6)
    "compliance_gdpr_canonical.json",       # GDPR (45 rules, IDs: Art. 33(1) – Art. 40)
    "compliance_hipaa_canonical.json",      # HIPAA (28 rules, IDs: §164.312(a)(1) – §164.316)
    "compliance_nist_800_53_canonical.json",# NIST 800-53 (42 rules, IDs: IR-1 – PE-3)
    "compliance_soc2_canonical.json",       # SOC 2 Type II (18 rules, IDs: CC6.1 – PI1.4)
    "compliance_cis_v8_canonical.json",     # CIS Controls v8 (25 rules, IDs: 5.1 – 17.9)
    "compliance_sebi_canonical.json",       # SEBI CSCRF (15 rules, IDs: 4.1.1 – 4.5.2)
    "compliance_dpdp_canonical.json",       # DPDP Act 2023 (12 rules, IDs: Sec 6 – Sec 12)
    "compliance_iso_42001_canonical.json",  # ISO 42001 (20 rules, IDs: 5.1.1 – 10.1.1)
    "compliance_nist_csf_canonical.json",   # NIST CSF 2.0 (18 rules, IDs: DE.AE-1 – ID.SC-4)
]

DATA_DIR = Path(__file__).parent


def merge_rules() -> list:
    """Merge all framework JSON files into a single list, assigned an index."""
    all_rules = []
    total_by_framework = {}

    for filename in FRAMEWORK_FILES:
        filepath = DATA_DIR / filename
        if not filepath.exists():
            print(f"  ⚠️  Missing: {filename} — skipping")
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            rules = json.load(f)

        framework_name = rules[0]["framework"] if rules else filename
        total_by_framework[framework_name] = len(rules)
        all_rules.extend(rules)
        print(f"  ✓ {filename}: {len(rules)} rules")

    print(f"\n  Total rules loaded: {len(all_rules)}")
    print("\n  Rule count by framework:")
    for fw, count in total_by_framework.items():
        print(f"    {fw}: {count}")

    return all_rules


def save_merged(rules: list):
    """Write the full merged rules list to compliance_rules_full.json."""
    output_path = DATA_DIR / "compliance_rules_full.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)
    print(f"\n  ✅ Saved to: {output_path}")
    print(f"  File size: {output_path.stat().st_size / 1024:.1f} KB")


def load_to_mongo(rules: list):
    """(Optional) Load rules into MongoDB soar.compliance_rules."""
    try:
        from pymongo import MongoClient, ASCENDING
    except ImportError:
        print("  ⚠️  pymongo not installed. Skipping MongoDB load.")
        return

    client = MongoClient("mongodb://localhost:27017/")
    db = client["soar"]
    collection = db["compliance_rules"]

    print("\n  Loading into MongoDB...")
    collection.drop()  # Clean import

    # Create indexes for fast query
    collection.create_index([("framework", ASCENDING)])
    collection.create_index([("tier", ASCENDING)])
    collection.create_index([("rule_type", ASCENDING)])
    collection.create_index([("control_id", ASCENDING)])
    collection.create_index([("applies_when.asset_compliance_scope", ASCENDING)])
    collection.create_index([("applies_when.asset_tags", ASCENDING)])
    collection.create_index([("applies_when.incident_type", ASCENDING)])
    collection.create_index([("applies_when.universal", ASCENDING)])  # Universal tier fast lookup
    collection.create_index([("blocked_actions", ASCENDING)])
    collection.create_index([("required_action", ASCENDING)])

    result = collection.insert_many(rules)
    print(f"  ✅ Inserted {len(result.inserted_ids)} rules into soar.compliance_rules")

    # Summary by framework
    print("\n  Verification — rules in MongoDB:")
    for fw in collection.distinct("framework"):
        count = collection.count_documents({"framework": fw})
        tier = "UNIVERSAL" if collection.count_documents({"framework": fw, "tier": "universal"}) > 0 else "scoped"
        print(f"    [{tier}] {fw}: {count} rules")

    # Universal tier count
    universal_count = collection.count_documents({"tier": "universal"})
    print(f"\n  Universal rules (apply to ALL incidents): {universal_count}")

    client.close()


if __name__ == "__main__":
    print("=" * 60)
    print("COMPLIANCE RULES MERGE SCRIPT")
    print("=" * 60)

    print("\n[1/3] Reading framework files...")
    rules = merge_rules()

    print("\n[2/3] Saving merged file...")
    save_merged(rules)

    if "--load-mongo" in sys.argv:
        print("\n[3/3] Loading into MongoDB...")
        load_to_mongo(rules)
    else:
        print("\n[3/3] Skipping MongoDB load (pass --load-mongo to enable).")

    print("\n✅ Done!")
