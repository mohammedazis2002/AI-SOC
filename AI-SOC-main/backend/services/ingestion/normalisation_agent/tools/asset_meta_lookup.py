"""
Asset Meta Lookup
=================
Enriches a ULF alert with a slim asset_meta block from the MongoDB
`asset_inventory` collection.

Lookup strategy (in priority order):
  1. src_endpoint.hostname  → exact match on asset_inventory.hostname
  2. src_endpoint.ip        → match on asset_inventory.ip_addresses[]
  3. dst_endpoint.hostname  → fallback if src not found
  4. dst_endpoint.ip        → fallback

If no asset is found in inventory, a conservative stub is built from
hostname pattern inference (environment, criticality, compliance zones).
`auto_stub: True` tells downstream consumers inventory is incomplete.

Slim schema (10 fields only — everything downstream actually uses):
  asset_id            str | null   — MongoDB doc ID (null if stub)
  hostname            str | null   — lookup key
  asset_type          str          — server / laptop / database_server / firewall / unknown
  environment         str          — production | staging | dev | test
  business_criticality str         — critical | high | medium | low
  data_classification str          — confidential | restricted | internal | public
  compliance_zones    list[str]    — ["pci_dss", "hipaa", "soc2", ...]
  has_pii             bool         — asset likely contains personal/customer data
  has_pci             bool         — asset likely contains financial/cardholder data
  auto_stub           bool         — True = not found in inventory, values are inferred

Downstream consumers:
  Auditor Agent          — business_criticality, data_classification, has_pii, has_pci
  Compliance Checker     — compliance_zones, environment, has_pii, has_pci
  Safety Checker         — environment ("production" = enforce backup/dep checks)
  Decision Engine        — business_criticality (asset risk proxy)
  Blast Radius Tool      — hostname (entity resolution key)
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Only fetch what we actually use
_PROJECTION = {
    "_id": 0,
    "asset_id": 1,
    "hostname": 1,
    "asset_type": 1,
    "environment": 1,
    "business_criticality": 1,
    "data_classification": 1,
    "compliance_zones": 1,
    "has_pii": 1,
    "has_pci": 1,
}

# Conservative defaults when asset not found in inventory
_STUB_DEFAULTS: Dict[str, Any] = {
    "asset_id": None,
    "hostname": None,
    "asset_type": "unknown",
    "environment": "production",  # safest assumption
    "business_criticality": "medium",
    "data_classification": "internal",
    "compliance_zones": [],
    "has_pii": False,
    "has_pci": False,
    "auto_stub": True,
}


async def run_asset_meta_lookup(
    ulf: Dict[str, Any],
    db=None,
) -> Dict[str, Any]:
    """
    Attach asset_meta to the alert dict.

    Args:
        ulf:  ULF alert dict (MITRE-enriched, pre-FP-detection)
        db:   Motor AsyncIOMotorDatabase. If None, returns stub defaults.

    Returns:
        The same dict with `alert["asset_meta"]` attached.
    """
    src_ep = ulf.get("src_endpoint") or {}
    dst_ep = ulf.get("dst_endpoint") or {}

    hostname = src_ep.get("hostname") or dst_ep.get("hostname")
    ip = src_ep.get("ip") or dst_ep.get("ip")

    if db is None:
        logger.debug("asset_meta_lookup: no DB client — attaching stub")
        ulf["asset_meta"] = _make_stub(hostname, ip)
        return ulf

    # FIX: _lookup is now async — must be awaited so Motor's coroutine
    #      resolves to a dict rather than returning a Future object.
    asset_doc = await _lookup(db, hostname, ip)

    if asset_doc:
        asset_doc["auto_stub"] = False
        ulf["asset_meta"] = asset_doc
        logger.info(
            f"asset_meta: found '{hostname or ip}' → "
            f"criticality={asset_doc.get('business_criticality')} "
            f"env={asset_doc.get('environment')} "
            f"zones={asset_doc.get('compliance_zones')}"
        )
    else:
        ulf["asset_meta"] = _make_stub(hostname, ip)
        logger.info(
            f"asset_meta: '{hostname or ip}' not in inventory — stub created. "
            "Populate asset_inventory for accurate CIA/compliance scoring."
        )

    return ulf


async def _lookup(
    db, hostname: Optional[str], ip: Optional[str]
) -> Optional[Dict[str, Any]]:
    """Try hostname then IP lookup against asset_inventory (async Motor)."""
    try:
        col = db.asset_inventory
        if hostname:
            # FIX: Was col.find_one(...) — blocking pymongo call that returns a
            #      Future when called on a Motor collection. Now awaited correctly.
            doc = await col.find_one({"hostname": hostname}, _PROJECTION)
            if doc:
                return doc
        if ip:
            doc = await col.find_one({"ip_addresses": ip}, _PROJECTION)
            if doc:
                return doc
    except Exception as e:
        logger.warning(f"asset_inventory query failed: {e}")
    return None


def _make_stub(hostname: Optional[str], ip: Optional[str]) -> Dict[str, Any]:
    """
    Build a conservative stub from hostname pattern inference.

    Inference rules (hostname patterns only — no ML, no external calls):
      environment       : prod/prd/live → production, staging/stg → staging,
                          dev → dev, test/qa → test
      business_criticality: payment/pci/card/billing → critical
                            db/database/sql/mongo → high
                            auth/sso/ldap/ad/idp → high
      compliance_zones  : payment/pci/card/billing → ["pci_dss"]
      has_pci           : same as above
      has_pii           : hr/people/crm/patient/patient → True
      data_classification: confidential for critical assets, else internal
    """
    stub = dict(_STUB_DEFAULTS)
    if hostname:
        stub["hostname"] = hostname
        h = hostname.lower()

        # Environment
        if any(p in h for p in ("prod", "prd", "live")):
            stub["environment"] = "production"
        elif any(p in h for p in ("staging", "stg", "preprod")):
            stub["environment"] = "staging"
        elif any(p in h for p in ("dev", "develop")):
            stub["environment"] = "dev"
        elif any(p in h for p in ("test", "qa")):
            stub["environment"] = "test"

        # Criticality + compliance
        if any(
            p in h for p in ("payment", "pay", "pci", "card", "billing", "checkout")
        ):
            stub["business_criticality"] = "critical"
            stub["data_classification"] = "confidential"
            stub["compliance_zones"] = ["pci_dss"]
            stub["has_pci"] = True
        elif any(
            p in h
            for p in ("db", "database", "sql", "mongo", "postgres", "redis", "elastic")
        ):
            stub["asset_type"] = "database_server"
            stub["business_criticality"] = "high"
            stub["data_classification"] = "restricted"
        elif any(p in h for p in ("auth", "sso", "ldap", "ad-", "idp", "iam", "okta")):
            stub["asset_type"] = "identity_provider"
            stub["business_criticality"] = "high"
        elif any(
            p in h for p in ("hr", "people", "crm", "patient", "clinic", "ehm", "ehr")
        ):
            stub["business_criticality"] = "high"
            stub["data_classification"] = "confidential"
            stub["has_pii"] = True

    if ip:
        stub["hostname"] = stub.get("hostname") or ip

    return stub
