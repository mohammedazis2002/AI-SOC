"""
Bootstrap: Manual Asset Registry (Servers, Network Gear, Cameras, etc.)
========================================================================
For assets not managed by JumpCloud (servers, firewalls, switches, printers,
cameras, biometrics) whose data comes from physical tracking spreadsheets.

Instead of parsing Excel files directly (fragile), this script reads a
structured JSON config file (`manual_assets.json`) that you fill in once
based on your spreadsheets. Fields map directly to asset_inventory schema.

Usage:
    # Step 1: Generate a template config
    python bootstrap_manual_assets.py --generate-template --output manual_assets.json

    # Step 2: Fill in manual_assets.json from your spreadsheets

    # Step 3: Import to MongoDB
    python bootstrap_manual_assets.py --config manual_assets.json

The JSON config structure is:
{
  "servers": [...],
  "network": [...],     (firewalls, switches, access points)
  "cameras": [...],
  "biometrics": [...],
  "printers": [...],
  "nvr": [...]
}
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

from pymongo import MongoClient, UpdateOne

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("bootstrap_manual")

# ── CIA baseline (same as CSV bootstrap) ─────────────────────────────────────
CIA_BASELINE = {
    "server":       {"c": 1,  "i": 1,  "a": 2,  "business_criticality": "low",      "sla_tier": "gold",     "data_classification": "internal"},
    "firewall":     {"c": 5,  "i": 5,  "a": 5,  "business_criticality": "critical",  "sla_tier": "platinum", "data_classification": "confidential"},
    "switch":       {"c": 1,  "i": 4,  "a": 5,  "business_criticality": "high",      "sla_tier": "platinum", "data_classification": "internal"},
    "access_point": {"c": 2,  "i": 4,  "a": 5,  "business_criticality": "high",      "sla_tier": "gold",     "data_classification": "internal"},
    "camera":       {"c": 2,  "i": 3,  "a": 5,  "business_criticality": "medium",    "sla_tier": "silver",   "data_classification": "internal"},
    "nvr":          {"c": 3,  "i": 4,  "a": 5,  "business_criticality": "high",      "sla_tier": "gold",     "data_classification": "sensitive"},
    "printer":      {"c": 3,  "i": 3,  "a": 2,  "business_criticality": "low",       "sla_tier": "bronze",   "data_classification": "internal"},
    "biometric":    {"c": 5,  "i": 5,  "a": 4,  "business_criticality": "critical",  "sla_tier": "gold",     "data_classification": "confidential"},
}

# Template with one example per asset_type — user fills these in from spreadsheets
TEMPLATE = {
    "servers": [
        {
            "hostname":               "server-01",             # Internal Hostname (from your sheet)
            "ip_addresses":           ["10.0.0.10"],           # OS IP Address
            "manufacturer":           "Dell",                  # Make
            "hardware_model":         "PowerEdge R640",        # Model
            "serial_number":          "SN123456",              # Serial No.
            "cpu":                    "Intel Xeon 8-core",     # CPU
            "memory_gb":              64,                      # RAM in GB
            "os":                     "Ubuntu 22.04 LTS",      # Installed OS
            "running_services":       ["nginx", "postgresql"],  # Running Services
            "license":                "OEM",                   # License
            "environment":            "production",
            "customer_facing":        False,
            "revenue_generating":     False,
            "backup_enabled":         True,
            "compliance_zones":       ["iso_27001_2022"],
            "tags":                   {}
        }
    ],
    "network": [
        {
            "type":          "firewall",                       # firewall | switch | access_point
            "hostname":      "fw-01",                         # Hostname (from your sheet)
            "ip_addresses":  ["192.168.1.1"],                 # IP Address
            "manufacturer":  "Fortinet",                      # Make
            "hardware_model": "FortiGate 60F",                # Model
            "serial_number": "FG60F00000000",                 # Serial No.
            "location":      "Server Room",                   # Asset Location
            "description":   "Primary perimeter firewall",
            "compliance_zones": ["iso_27001_2022"],
            "tags":          {}
        },
        {
            "type":          "switch",
            "hostname":      "sw-01",
            "ip_addresses":  ["192.168.1.2"],
            "manufacturer":  "Cisco",
            "hardware_model": "Catalyst 2960",
            "serial_number": "CISCO12345",
            "location":      "Server Room",
            "description":   "Core LAN switch",
            "compliance_zones": ["iso_27001_2022"],
            "tags":          {}
        }
    ],
    "cameras": [
        {
            "hostname":      "cam-01",
            "ip_addresses":  ["10.0.2.10"],
            "manufacturer":  "Hikvision",
            "hardware_model": "DS-2CD2T47G2-L",
            "serial_number": "HIK12345",
            "description":   "Entrance camera",
            "location":      "Main Entrance",
            "compliance_zones": ["iso_27001_2022"],
            "tags":          {}
        }
    ],
    "nvr": [
        {
            "hostname":      "nvr-01",
            "ip_addresses":  ["10.0.2.1"],
            "manufacturer":  "Hikvision",
            "hardware_model": "DS-7616NI-K2",
            "serial_number": "NVR12345",
            "description":   "NVR for all cameras",
            "compliance_zones": ["iso_27001_2022"],
            "tags":          {}
        }
    ],
    "biometrics": [
        {
            "hostname":      "bio-01",
            "ip_addresses":  ["10.0.3.10"],
            "manufacturer":  "ZKTeco",
            "hardware_model": "F18",
            "serial_number": "ZK12345",
            "description":   "Main door biometric",
            "location":      "Main Entrance",
            "compliance_zones": ["iso_27001_2022"],
            "tags":          {}
        }
    ],
    "printers": [
        {
            "hostname":      "printer-01",
            "ip_addresses":  ["10.0.1.50"],
            "manufacturer":  "HP",
            "hardware_model": "LaserJet Pro M404n",
            "serial_number": "HP12345",
            "description":   "Office printer",
            "compliance_zones": ["iso_27001_2022"],
            "tags":          {}
        }
    ]
}


def _make_asset_id(hostname: str, asset_type: str) -> str:
    """Deterministic asset_id from hostname + type."""
    import hashlib
    return "man-" + hashlib.md5(f"{asset_type}::{hostname}".encode()).hexdigest()[:12]


def transform_asset(raw: Dict[str, Any], asset_type: str) -> Dict[str, Any]:
    cia = CIA_BASELINE.get(asset_type, {
        "c": 3, "i": 3, "a": 3,
        "business_criticality": "medium",
        "sla_tier": "silver",
        "data_classification": "internal",
    })

    hostname = raw.get("hostname", "")
    return {
        "asset_id":              _make_asset_id(hostname, asset_type),
        "hostname":              hostname,
        "computer_name":         hostname,
        "ip_addresses":          raw.get("ip_addresses", []),
        "mac_address":           raw.get("mac_address"),
        "network_segment":       raw.get("network_segment"),
        "asset_type":            asset_type,
        "environment":           raw.get("environment", "production"),
        "manufacturer":          raw.get("manufacturer", ""),
        "hardware_model":        raw.get("hardware_model", ""),
        "serial_number":         raw.get("serial_number", ""),
        "os":                    raw.get("os", ""),
        "cpu":                   raw.get("cpu", ""),
        "memory_gb":             raw.get("memory_gb"),
        "running_services":      raw.get("running_services", []),
        "description":           raw.get("description", ""),
        "location":              raw.get("location", ""),
        # CIA rubric
        "business_criticality":  cia["business_criticality"],
        "sla_tier":              cia["sla_tier"],
        "data_classification":   cia["data_classification"],
        "backup_enabled":        raw.get("backup_enabled", cia.get("backup_enabled", False)),
        "recovery_time_objective_minutes": raw.get("rto_minutes", 240),
        "revenue_generating":    raw.get("revenue_generating", False),
        "customer_facing":       raw.get("customer_facing", False),
        "contains_credentials":  asset_type == "biometric",
        "contains_customer_data": False,
        "contains_financial_data": False,
        "regulatory_tags":       [],
        "compliance_zones":      raw.get("compliance_zones", ["iso_27001_2022"]),
        "service_tier":          None,
        "tags":                  raw.get("tags", {}),
        "accessed_by_users":     [],
        "depends_on":            [],
        "connected_to":          [],
        "cia_scores":            {"c": cia["c"], "i": cia["i"], "a": cia["a"]},
        "last_seen":             datetime.now(timezone.utc).isoformat(),
        "source":                "manual",
        "auto_stub":             False,
    }


def load_and_transform(config_path: str) -> List[Dict[str, Any]]:
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    assets: List[Dict] = []

    for asset_type, section_key in [
        ("server",      "servers"),
        ("camera",      "cameras"),
        ("nvr",         "nvr"),
        ("biometric",   "biometrics"),
        ("printer",     "printers"),
    ]:
        for raw in config.get(section_key, []):
            assets.append(transform_asset(raw, asset_type))

    # Network devices have type inside the record
    for raw in config.get("network", []):
        atype = raw.get("type", "switch")
        assets.append(transform_asset(raw, atype))

    return assets


def write_to_mongo(assets: List[Dict], mongo_uri: str, db_name: str) -> None:
    client = MongoClient(mongo_uri)
    db     = client[db_name]
    ops    = [
        UpdateOne({"asset_id": a["asset_id"]}, {"$set": a}, upsert=True)
        for a in assets
    ]
    if ops:
        result = db.asset_inventory.bulk_write(ops)
        logger.info(
            f"asset_inventory: {result.upserted_count} inserted, "
            f"{result.modified_count} updated"
        )
    db.asset_inventory.create_index("hostname")
    db.asset_inventory.create_index("ip_addresses")
    db.asset_inventory.create_index("asset_id", unique=True)
    logger.info("Indexes verified")


def main():
    parser = argparse.ArgumentParser(description="Bootstrap manual assets into asset_inventory")
    parser.add_argument("--config",            help="Path to manual_assets.json")
    parser.add_argument("--generate-template", action="store_true",
                        help="Generate a blank template JSON and exit")
    parser.add_argument("--output",    default="manual_assets.json",
                        help="Output path for template (with --generate-template)")
    parser.add_argument("--mongo-uri", default="mongodb://localhost:27017")
    parser.add_argument("--db-name",   default="soar_db")
    parser.add_argument("--dry-run",   action="store_true")
    args = parser.parse_args()

    if args.generate_template:
        out = args.output
        with open(out, "w", encoding="utf-8") as f:
            json.dump(TEMPLATE, f, indent=2)
        logger.info(f"Template written to: {out}")
        logger.info("Edit this file with your actual asset details, then re-run without --generate-template")
        return

    if not args.config:
        parser.error("--config is required unless using --generate-template")

    assets = load_and_transform(args.config)
    logger.info(f"Loaded {len(assets)} manual assets")

    if args.dry_run:
        print(json.dumps(assets[:2], indent=2, default=str))
        print(f"\n--- {len(assets)} total assets ---")
        return

    write_to_mongo(assets, args.mongo_uri, args.db_name)
    logger.info(f"Done. {len(assets)} assets written to '{args.db_name}'")


if __name__ == "__main__":
    main()
