"""
Bootstrap: Asset Inventory from JumpCloud REST API
===================================================
Pulls live device and user data from the JumpCloud REST API and populates
MongoDB `asset_inventory` and `user_inventory`.

Usage:
    export JUMPCLOUD_API_KEY="your_api_key_here"
    python bootstrap_jumpcloud_api.py

    # Or with explicit args:
    python bootstrap_jumpcloud_api.py \\
        --api-key <key> \\
        --mongo-uri mongodb://localhost:27017 \\
        --db-name soar_db

JumpCloud API Docs: https://docs.jumpcloud.com/api/1.0/index.html
Auth: x-api-key header

Key endpoints used:
    GET /api/systems          — all managed devices
    GET /api/systemusers      — all user accounts
    GET /api/v2/systems/{id}/associations?targets=user  — user↔device link
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from pymongo import MongoClient, UpdateOne

# Import CIA baseline and helpers from the CSV bootstrap script
sys.path.insert(0, os.path.dirname(__file__))
from bootstrap_asset_inventory_csv import (
    CIA_BASELINE, _infer_asset_type, _infer_env, infer_dependencies, write_to_mongo
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("bootstrap_api")

JUMPCLOUD_BASE  = "https://console.jumpcloud.com"
API_V1          = f"{JUMPCLOUD_BASE}/api"
API_V2          = f"{JUMPCLOUD_BASE}/api/v2"
PAGE_SIZE       = 100
RATE_LIMIT_WAIT = 0.5   # seconds between paginated requests


class JumpCloudClient:
    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers.update({
            "x-api-key":    api_key,
            "Accept":       "application/json",
            "Content-Type": "application/json",
        })

    def _get_all(self, url: str, params: Optional[Dict] = None) -> List[Dict]:
        """Paginate through all results from a JumpCloud GET endpoint."""
        results = []
        skip = 0
        params = params or {}

        while True:
            params.update({"limit": PAGE_SIZE, "skip": skip})
            resp = self.session.get(url, params=params, timeout=30)
            resp.raise_for_status()

            data = resp.json()
            # V1 returns {"results": [...], "totalCount": N}
            # V2 returns [...] directly
            if isinstance(data, list):
                batch = data
            else:
                batch = data.get("results", [])

            results.extend(batch)
            logger.debug(f"  Fetched {len(batch)} records (total so far: {len(results)})")

            if len(batch) < PAGE_SIZE:
                break
            skip += PAGE_SIZE
            time.sleep(RATE_LIMIT_WAIT)

        return results

    def get_systems(self) -> List[Dict]:
        logger.info("Fetching all systems from JumpCloud API...")
        return self._get_all(f"{API_V1}/systems", {"fields": (
            "id hostname displayName os active templateName "
            "organization serialNumber version "
            "networkInterfaces lastContact"
        )})

    def get_users(self) -> List[Dict]:
        logger.info("Fetching all system users from JumpCloud API...")
        return self._get_all(f"{API_V1}/systemusers", {"fields": (
            "id username firstname lastname email "
            "admin suspended activated "
            "lastUpdated created"
        )})

    def get_system_associations(self, system_id: str) -> List[str]:
        """Return list of user_ids associated with a system."""
        try:
            data = self._get_all(
                f"{API_V2}/systems/{system_id}/associations",
                {"targets": "user"}
            )
            return [item.get("to", {}).get("id", "") for item in data if item.get("to")]
        except requests.HTTPError as e:
            logger.warning(f"  Association fetch failed for {system_id}: {e}")
            return []

    def get_user_systems(self, user_id: str) -> List[str]:
        """Return list of system_ids a user is associated with."""
        try:
            data = self._get_all(
                f"{API_V2}/users/{user_id}/associations",
                {"targets": "system"}
            )
            return [item.get("to", {}).get("id", "") for item in data if item.get("to")]
        except Exception as e:
            logger.warning(f"  User-system fetch failed for {user_id}: {e}")
            return []


def build_asset_from_api(sys_doc: Dict, user_map: Dict[str, str]) -> Dict[str, Any]:
    """
    Transform a JumpCloud API system record into an asset_inventory document.
    user_map: {user_id → username}
    """
    sid      = sys_doc.get("id", "")
    hostname = (
        sys_doc.get("hostname")
        or sys_doc.get("displayName")
        or ""
    )
    hardware = sys_doc.get("version", "")
    atype    = _infer_asset_type(hostname, hardware)
    cia      = CIA_BASELINE.get(atype, CIA_BASELINE["unknown"])

    # IP addresses from networkInterfaces (API v1 format)
    ip_addresses = []
    mac_address  = None
    network_interfaces = sys_doc.get("networkInterfaces") or []
    for iface in network_interfaces:
        for ip in iface.get("ips", []):
            addr = ip.strip()
            if addr and not addr.startswith("127.") and not addr.startswith("::1"):
                ip_addresses.append(addr)
        if not mac_address:
            mac = iface.get("hardwareAddr", "").strip()
            if mac and mac != "00:00:00:00:00:00":
                mac_address = mac.upper()

    return {
        "asset_id":              sid,
        "hostname":              hostname,
        "computer_name":         sys_doc.get("displayName") or hostname,
        "ip_addresses":          list(dict.fromkeys(ip_addresses)),
        "mac_address":           mac_address,
        "network_segment":       None,   # needs interfaceAddress CSV for CIDR
        "asset_type":            atype,
        "environment":           _infer_env(hostname),
        "manufacturer":          "",
        "hardware_model":        hardware,
        "serial_number":         sys_doc.get("serialNumber") or "",
        "os":                    sys_doc.get("os") or "",
        # CIA rubric fields
        "business_criticality":  cia["business_criticality"],
        "sla_tier":              cia["sla_tier"],
        "data_classification":   cia["data_classification"],
        "backup_enabled":        cia.get("backup_enabled", False),
        "recovery_time_objective_minutes": 480,
        "revenue_generating":    False,
        "customer_facing":       False,
        "contains_credentials":  cia.get("contains_credentials", False),
        "contains_customer_data": False,
        "contains_financial_data": False,
        "regulatory_tags":       [],
        "compliance_zones":      cia["compliance_zones"],
        "service_tier":          None,
        "tags":                  {
            "active":            sys_doc.get("active", True),
            "template":          sys_doc.get("templateName", ""),
        },
        # Relationship fields (will be updated by association pass)
        "accessed_by_users":     [],
        "running_services":      [],
        "depends_on":            [],
        "connected_to":          [],
        # Metadata
        "cia_scores":            {"c": cia["c"], "i": cia["i"], "a": cia["a"]},
        "last_seen":             sys_doc.get("lastContact") or datetime.now(timezone.utc).isoformat(),
        "source":                "jumpcloud_api",
        "auto_stub":             False,
    }


def build_user_from_api(user_doc: Dict, device_ids: List[str]) -> Dict[str, Any]:
    return {
        "user_id":      user_doc.get("id", ""),
        "username":     user_doc.get("username", ""),
        "email":        user_doc.get("email") or "",
        "first_name":   user_doc.get("firstname") or "",
        "last_name":    user_doc.get("lastname") or "",
        "is_admin":     user_doc.get("admin", False),
        "is_suspended": user_doc.get("suspended", False),
        "is_activated": user_doc.get("activated", False),
        "device_ids":   device_ids,
        "source":       "jumpcloud_api",
        "last_updated": user_doc.get("lastUpdated") or datetime.now(timezone.utc).isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="Bootstrap asset_inventory from JumpCloud API")
    parser.add_argument("--api-key",   default=os.getenv("JUMPCLOUD_API_KEY"),
                        help="JumpCloud API key (or set JUMPCLOUD_API_KEY env var)")
    parser.add_argument("--mongo-uri", default=os.getenv("MONGO_URI", "mongodb://localhost:27017"))
    parser.add_argument("--db-name",   default="soar_db")
    parser.add_argument("--dry-run",   action="store_true")
    parser.add_argument("--skip-assoc", action="store_true",
                        help="Skip user-system association fetch (faster, less accurate)")
    args = parser.parse_args()

    if not args.api_key:
        logger.error("No API key. Set JUMPCLOUD_API_KEY or pass --api-key")
        sys.exit(1)

    client = JumpCloudClient(args.api_key)

    # 1. Fetch systems + users
    systems = client.get_systems()
    users   = client.get_users()
    logger.info(f"Fetched {len(systems)} systems, {len(users)} users")

    user_id_to_doc = {u["id"]: u for u in users}

    # 2. User↔system associations
    system_to_users: Dict[str, List[str]] = {}
    user_to_systems: Dict[str, List[str]] = {u["id"]: [] for u in users}

    if not args.skip_assoc:
        for sys_doc in systems:
            sid = sys_doc["id"]
            logger.info(f"  Fetching associations for system {sid} ({sys_doc.get('hostname', '')})")
            user_ids = client.get_system_associations(sid)
            system_to_users[sid] = [
                user_id_to_doc[uid]["username"]
                for uid in user_ids
                if uid in user_id_to_doc
            ]
            for uid in user_ids:
                if uid in user_to_systems:
                    user_to_systems[uid].append(sid)

    # 3. Build documents
    assets = []
    for sys_doc in systems:
        asset = build_asset_from_api(sys_doc, user_id_to_doc)
        asset["accessed_by_users"] = system_to_users.get(sys_doc["id"], [])
        assets.append(asset)

    assets = infer_dependencies(assets)

    user_records = [
        build_user_from_api(u, user_to_systems.get(u["id"], []))
        for u in users
    ]

    if args.dry_run:
        print(json.dumps(assets[:2], indent=2, default=str))
        print(f"\n--- {len(assets)} assets, {len(user_records)} users ---")
        return

    write_to_mongo(assets, user_records, args.mongo_uri, args.db_name)
    logger.info(f"Done. {len(assets)} assets, {len(user_records)} users written.")


if __name__ == "__main__":
    main()
