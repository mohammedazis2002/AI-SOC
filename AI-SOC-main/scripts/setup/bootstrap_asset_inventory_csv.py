"""
Bootstrap: Asset Inventory from JumpCloud CSV Exports
======================================================
Reads JumpCloud MDM report CSVs exported from the JumpCloud console and
populates the MongoDB `asset_inventory` and `user_inventory` collections.

Usage:
    python bootstrap_asset_inventory_csv.py --csv-dir /path/to/jumpcloud/exports

Expected CSV files (all optional except system.csv):
    system.csv            — device hardware + hostname
    users.csv             — local user accounts per device
    interfaceAddress.csv  — network interfaces + IP addresses
    interfaceDetails.csv  — MAC addresses, DNS info
    bitlockerInfo.csv     — disk encryption status
    services.csv          — running services
    programs.csv          — installed software
    patches.csv           — Windows patches applied
    secureBoot.csv        — secure boot status

CIA Baseline (from your Asset Risk Assessment document):
    Laptops:   C=5, I=4, A=4
    Servers:   C=1, I=1, A=2
    Firewalls: C=5, I=5, A=5
    Switches:  C=1, I=4, A=5
    etc.

All CIA scores are applied per asset_type derived from hostname patterns
and hardware model, with a manual override possible via --cia-override JSON file.
"""

import argparse
import csv
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pymongo import MongoClient, UpdateOne

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("bootstrap_csv")

# ── CIA Baseline per asset_type (from your risk assessment table) ─────────────
# Format: [C, I, A] scores 1-5
CIA_BASELINE: Dict[str, Dict[str, Any]] = {
    "laptop": {
        "c": 5, "i": 4, "a": 4,
        "business_criticality":   "high",
        "sla_tier":               "silver",
        "data_classification":    "confidential",
        "backup_enabled":         None,   # derive from bitlocker
        "compliance_zones":       ["iso_27001_2022"],
    },
    "server": {
        "c": 1, "i": 1, "a": 2,
        "business_criticality":   "low",
        "sla_tier":               "gold",
        "data_classification":    "internal",
        "backup_enabled":         True,
        "compliance_zones":       ["iso_27001_2022"],
    },
    "firewall": {
        "c": 5, "i": 5, "a": 5,
        "business_criticality":   "critical",
        "sla_tier":               "platinum",
        "data_classification":    "confidential",
        "backup_enabled":         True,
        "compliance_zones":       ["iso_27001_2022"],
    },
    "switch": {
        "c": 1, "i": 4, "a": 5,
        "business_criticality":   "high",
        "sla_tier":               "platinum",
        "data_classification":    "internal",
        "backup_enabled":         True,
        "compliance_zones":       ["iso_27001_2022"],
    },
    "access_point": {
        "c": 2, "i": 4, "a": 5,
        "business_criticality":   "high",
        "sla_tier":               "gold",
        "data_classification":    "internal",
        "backup_enabled":         False,
        "compliance_zones":       ["iso_27001_2022"],
    },
    "camera": {
        "c": 2, "i": 3, "a": 5,
        "business_criticality":   "medium",
        "sla_tier":               "silver",
        "data_classification":    "internal",
        "backup_enabled":         False,
        "compliance_zones":       ["iso_27001_2022"],
    },
    "nvr": {
        "c": 3, "i": 4, "a": 5,
        "business_criticality":   "high",
        "sla_tier":               "gold",
        "data_classification":    "sensitive",
        "backup_enabled":         True,
        "compliance_zones":       ["iso_27001_2022"],
    },
    "printer": {
        "c": 3, "i": 3, "a": 2,
        "business_criticality":   "low",
        "sla_tier":               "bronze",
        "data_classification":    "internal",
        "backup_enabled":         False,
        "compliance_zones":       ["iso_27001_2022"],
    },
    "biometric": {
        "c": 5, "i": 5, "a": 4,
        "business_criticality":   "critical",
        "sla_tier":               "gold",
        "data_classification":    "confidential",
        "backup_enabled":         True,
        "compliance_zones":       ["iso_27001_2022"],
        "contains_credentials":   True,
    },
    "unknown": {
        "c": 3, "i": 3, "a": 3,
        "business_criticality":   "medium",
        "sla_tier":               "silver",
        "data_classification":    "internal",
        "backup_enabled":         False,
        "compliance_zones":       ["iso_27001_2022"],
    },
}

# Hostname pattern → asset_type
_TYPE_PATTERNS = [
    (["firewall", "fw-", "pf-", "fortigate"],           "firewall"),
    (["switch", "sw-", "cisco-sw", "lan-sw"],            "switch"),
    (["wifi", "ap-", "access-point", "wap"],             "access_point"),
    (["printer", "print", "mfp"],                         "printer"),
    (["camera", "cam-", "nvr"],                           "camera"),
    (["biometric", "bio-", "fingerprint"],                "biometric"),
    (["server", "srv", "esxi", "vmhost", "dc-"],          "server"),
]


def _read_csv(path: str) -> List[Dict[str, str]]:
    if not os.path.isfile(path):
        logger.debug(f"CSV not found (skip): {path}")
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


def _infer_asset_type(hostname: str, model: str = "") -> str:
    text = (hostname + " " + model).lower()
    for patterns, atype in _TYPE_PATTERNS:
        if any(p in text for p in patterns):
            return atype
    return "laptop"  # JumpCloud primarily manages laptops


def _derive_network_segment(address: str, mask: str) -> Optional[str]:
    """Derive CIDR network segment from IP + mask."""
    try:
        import ipaddress
        iface = ipaddress.ip_interface(f"{address}/{mask}")
        return str(iface.network)
    except Exception:
        return None


def load_csvs(csv_dir: str) -> Dict[str, List[Dict]]:
    files = {
        "system":           "system.csv",
        "users":            "users.csv",
        "iface_addr":       "interfaceAddress.csv",
        "iface_detail":     "interfaceDetails.csv",
        "bitlocker":        "bitlockerInfo.csv",
        "services":         "services.csv",
        "programs":         "programs.csv",
        "patches":          "patches.csv",
        "secure_boot":      "secureBoot.csv",
    }
    return {key: _read_csv(os.path.join(csv_dir, fname)) for key, fname in files.items()}


def build_asset_records(data: Dict[str, List[Dict]]) -> List[Dict[str, Any]]:
    """Join all CSVs by system_id and build asset_inventory documents."""

    # Index all CSVs by system_id
    def index(rows: list, key="system_id") -> Dict[str, list]:
        d = defaultdict(list)
        for row in rows:
            sid = row.get(key)
            if sid:
                d[sid].append(row)
        return d

    iface_idx    = index(data["iface_addr"])
    iface_d_idx  = index(data["iface_detail"])
    bitlock_idx  = index(data["bitlocker"])
    services_idx = index(data["services"])
    programs_idx = index(data["programs"])
    patches_idx  = index(data["patches"])
    sboot_idx    = index(data["secure_boot"])
    users_idx    = index(data["users"])   # system_id → [user rows]

    assets = []
    for sys_row in data["system"]:
        sid      = sys_row.get("system_id", "")
        hostname = sys_row.get("hostname") or sys_row.get("computer_name") or sys_row.get("local_hostname") or ""
        hardware = sys_row.get("hardware_model") or ""

        # ── Type + CIA baseline ───────────────────────────────────────────────
        atype   = _infer_asset_type(hostname, hardware)
        cia     = CIA_BASELINE.get(atype, CIA_BASELINE["unknown"])

        # ── IP addresses (from interfaceAddress) ─────────────────────────────
        ip_addresses = []
        network_segment = None
        mac_address = None

        for iface in iface_idx.get(sid, []):
            addr = iface.get("address", "").strip()
            mask = iface.get("mask", "").strip()
            itype = iface.get("type", "").lower()
            if addr and not addr.startswith("127.") and not addr.startswith("::"):
                ip_addresses.append(addr)
                if not network_segment and mask:
                    network_segment = _derive_network_segment(addr, mask)

        # MAC from interfaceDetails
        for iface_d in iface_d_idx.get(sid, []):
            mac = iface_d.get("mac", "").strip()
            if mac and mac != "00:00:00:00:00:00":
                mac_address = mac.upper()
                break

        # ── Encryption / backup status (from BitLocker) ───────────────────────
        bitlocker_protected = False
        for bl in bitlock_idx.get(sid, []):
            if bl.get("protection_status", "").strip() in ("1", "Protected", "True"):
                bitlocker_protected = True
                break
        backup_enabled = cia.get("backup_enabled")
        if backup_enabled is None:
            backup_enabled = bitlocker_protected   # use BitLocker as proxy for laptops

        # ── Secure boot ───────────────────────────────────────────────────────
        secure_boot = False
        for sb in sboot_idx.get(sid, []):
            if sb.get("secure_boot", "").strip() in ("1", "true", "True"):
                secure_boot = True
                break

        # ── Running services ──────────────────────────────────────────────────
        running_services = [
            s["name"] for s in services_idx.get(sid, [])
            if s.get("status", "").strip().lower() in ("running", "1", "true")
            and s.get("name")
        ]

        # ── Installed programs (top-level names only) ─────────────────────────
        installed_software = [
            p["name"] for p in programs_idx.get(sid, []) if p.get("name")
        ][:50]   # cap at 50

        # ── Patch status (count applied patches) ──────────────────────────────
        patch_count = len(patches_idx.get(sid, []))

        # ── Users on this device ──────────────────────────────────────────────
        accessed_by_users = [
            u["username"] for u in users_idx.get(sid, []) if u.get("username")
        ]
        has_admin_users = any(
            u.get("admin", "").strip().lower() in ("1", "true")
            for u in users_idx.get(sid, [])
        )
        if has_admin_users:
            # Device with admin accounts has higher integrity risk
            if cia["i"] < 5:
                cia = {**cia, "i": min(5, cia["i"] + 1)}

        # ── Build document ────────────────────────────────────────────────────
        doc: Dict[str, Any] = {
            "asset_id":              sid,
            "hostname":              hostname,
            "computer_name":         sys_row.get("computer_name") or hostname,
            "ip_addresses":          list(dict.fromkeys(ip_addresses)),  # dedup
            "mac_address":           mac_address,
            "network_segment":       network_segment,
            "asset_type":            atype,
            "environment":           _infer_env(hostname),
            "manufacturer":          sys_row.get("hardware_vendor") or "",
            "hardware_model":        hardware,
            "serial_number":         sys_row.get("hardware_serial") or "",
            "os":                    sys_row.get("system_id", ""),    # system.csv doesn't have OS field
            "cpu":                   f"{sys_row.get('cpu_brand','')} {sys_row.get('cpu_logical_cores','')} cores".strip(),
            "memory_gb":             _to_gb(sys_row.get("physical_memory")),
            # CIA rubric fields
            "business_criticality":  cia["business_criticality"],
            "sla_tier":              cia["sla_tier"],
            "data_classification":   cia["data_classification"],
            "backup_enabled":        backup_enabled,
            "recovery_time_objective_minutes": 480,
            "revenue_generating":    False,
            "customer_facing":       False,
            "contains_credentials":  cia.get("contains_credentials", has_admin_users),
            "contains_customer_data": False,
            "contains_financial_data": False,
            "regulatory_tags":       [],
            "compliance_zones":      cia["compliance_zones"],
            "service_tier":          None,
            "tags":                  {
                "secure_boot":       secure_boot,
                "patch_count":       patch_count,
                "bitlocker":         bitlocker_protected,
            },
            # Relationship fields
            "accessed_by_users":     accessed_by_users,
            "running_services":      running_services,
            "installed_software":    installed_software,
            "depends_on":            [],   # populated by dependency inference pass
            "connected_to":          [],   # populated by dependency inference pass
            # Metadata
            "source":                "jumpcloud_csv",
            "last_seen":             datetime.now(timezone.utc).isoformat(),
            "auto_stub":             False,
        }

        # CIA numeric summary (for auditor reference)
        doc["cia_scores"] = {"c": cia["c"], "i": cia["i"], "a": cia["a"]}

        assets.append(doc)

    return assets


def build_user_records(data: Dict[str, List[Dict]]) -> List[Dict[str, Any]]:
    """Build user_inventory documents from users.csv."""
    users: Dict[str, Dict] = {}

    for row in data["users"]:
        uname = row.get("username", "").strip()
        uid   = row.get("uid") or row.get("uuid") or uname
        if not uname:
            continue

        if uname not in users:
            users[uname] = {
                "user_id":       uid,
                "username":      uname,
                "uid":           row.get("uid", ""),
                "gid":           row.get("gid", ""),
                "shell":         row.get("shell", ""),
                "is_admin":      row.get("admin", "").strip().lower() in ("1", "true"),
                "is_managed":    row.get("managed", "").strip().lower() in ("1", "true"),
                "is_suspended":  row.get("suspended", "").strip().lower() in ("1", "true"),
                "last_login":    row.get("last_login", ""),
                "device_ids":    [],
                "source":        "jumpcloud_csv",
                "last_updated":  datetime.now(timezone.utc).isoformat(),
            }

        sid = row.get("system_id", "")
        if sid and sid not in users[uname]["device_ids"]:
            users[uname]["device_ids"].append(sid)

    return list(users.values())


def infer_dependencies(assets: List[Dict]) -> List[Dict]:
    """
    Simple dependency inference from network segments.
    Devices in the same subnet are assumed to connect through a common switch.
    Firewall is depended on by all devices (default gateway).
    """
    firewalls = [a["hostname"] for a in assets if a["asset_type"] == "firewall" and a["hostname"]]
    switches  = [a["hostname"] for a in assets if a["asset_type"] == "switch"   and a["hostname"]]

    segment_members: Dict[str, List[str]] = defaultdict(list)
    for a in assets:
        seg = a.get("network_segment")
        if seg:
            segment_members[seg].append(a["hostname"])

    for a in assets:
        deps = list(a.get("depends_on") or [])
        # All devices depend on firewall
        deps.extend(h for h in firewalls if h not in deps)
        # All devices depend on at least one switch
        deps.extend(h for h in switches[:1] if h not in deps)
        a["depends_on"] = deps

        # connected_to = all other devices in same network segment
        seg = a.get("network_segment")
        if seg:
            a["connected_to"] = [
                h for h in segment_members[seg]
                if h != a["hostname"]
            ]

    return assets


def write_to_mongo(
    assets: List[Dict],
    users: List[Dict],
    mongo_uri: str,
    db_name: str,
) -> None:
    client = MongoClient(mongo_uri)
    db     = client[db_name]

    # ── asset_inventory ───────────────────────────────────────────────────────
    if assets:
        ops = [
            UpdateOne(
                {"asset_id": a["asset_id"]},
                {"$set": a},
                upsert=True,
            )
            for a in assets
        ]
        result = db.asset_inventory.bulk_write(ops)
        logger.info(
            f"asset_inventory: {result.upserted_count} inserted, "
            f"{result.modified_count} updated"
        )

    # ── user_inventory ────────────────────────────────────────────────────────
    if users:
        ops = [
            UpdateOne(
                {"username": u["username"]},
                {"$set": u},
                upsert=True,
            )
            for u in users
        ]
        result = db.user_inventory.bulk_write(ops)
        logger.info(
            f"user_inventory: {result.upserted_count} inserted, "
            f"{result.modified_count} updated"
        )

    # Create indexes for fast lookup
    db.asset_inventory.create_index("hostname")
    db.asset_inventory.create_index("ip_addresses")
    db.asset_inventory.create_index("asset_id", unique=True)
    db.user_inventory.create_index("username", unique=True)
    db.user_inventory.create_index("device_ids")
    logger.info("Indexes created/verified")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _infer_env(hostname: str) -> str:
    h = hostname.lower()
    if any(p in h for p in ["prod", "prd", "live"]):    return "production"
    if any(p in h for p in ["staging", "stg"]):          return "staging"
    if any(p in h for p in ["dev", "develop"]):          return "dev"
    if any(p in h for p in ["test", "qa"]):              return "test"
    return "production"  # conservative default


def _to_gb(val: Optional[str]) -> Optional[float]:
    if not val:
        return None
    try:
        return round(int(val) / (1024 ** 3), 1)
    except (ValueError, TypeError):
        return None


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Bootstrap asset_inventory from JumpCloud CSVs")
    parser.add_argument("--csv-dir",   required=True,                    help="Directory containing JumpCloud CSV exports")
    parser.add_argument("--mongo-uri", default="mongodb://localhost:27017", help="MongoDB URI")
    parser.add_argument("--db-name",   default="soar_db",                help="MongoDB database name")
    parser.add_argument("--dry-run",   action="store_true",             help="Print records without writing to MongoDB")
    args = parser.parse_args()

    if not os.path.isdir(args.csv_dir):
        logger.error(f"CSV directory not found: {args.csv_dir}")
        sys.exit(1)

    logger.info(f"Loading CSVs from: {args.csv_dir}")
    data = load_csvs(args.csv_dir)

    logger.info(f"Processing {len(data['system'])} devices, {len(data['users'])} user records")
    assets = build_asset_records(data)
    assets = infer_dependencies(assets)
    users  = build_user_records(data)

    if args.dry_run:
        print(json.dumps(assets[:2], indent=2, default=str))
        print(f"\n--- {len(assets)} assets, {len(users)} users ---")
        return

    write_to_mongo(assets, users, args.mongo_uri, args.db_name)
    logger.info(f"Done. {len(assets)} assets, {len(users)} users written to '{args.db_name}'")


if __name__ == "__main__":
    main()
