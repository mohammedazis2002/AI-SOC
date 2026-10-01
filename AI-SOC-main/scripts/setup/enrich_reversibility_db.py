"""
Reversibility DB Enrichment Script
=====================================
Two jobs in one:
  1. Add reversibility_tier (1-4) to every existing entry in reversibility_db_full.json
     using the four-field rubric (reversible, rollback_automated, risk_category, data_loss_risk).

  2. Merge any action_catalog action_types that are MISSING from the DB into the DB
     (as properly-tiered entries) so reversibility_db_full.json is the single source
     of truth for all action metadata.

Tier Rubric:
  Tier 1 — Trivial / Instant
    reversible + rollback_automated + risk low/medium + no data loss + downtime < 5min

  Tier 2 — Moderate / IT Intervention
    reversible but manual rollback, OR high-risk but still reversible,
    OR causes temporary disruption (downtime 5-60min), OR data at risk is just config

  Tier 3 — Destructive / Hard to Reverse
    irreversible with risk=high, OR data loss (files, credentials, service state),
    OR requires backup to recover, OR downtime > 60min

  Tier 4 — Permanent / Structural Damage
    risk_category=critical, OR data_loss_risk contains "permanent",
    OR irreversible with permanent downtime (time_window_hours=0, no rollback)

Usage:
    python scripts/setup/enrich_reversibility_db.py
"""

import json
import os
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "../../backend/data/reversibility_db_full.json")


# ── Tier computation rubric ───────────────────────────────────────────────────

def compute_tier(entry: dict) -> int:
    risk      = entry.get("risk_category", "medium").lower()
    reversible = entry.get("reversible", False)
    automated  = entry.get("rollback_automated", False)
    data_loss  = str(entry.get("data_loss_risk", "none")).lower()
    downtime   = entry.get("estimated_downtime_minutes", 0) or 0

    # Tier 4: Permanent destruction — cannot recover under any circumstances
    if risk == "critical":
        return 4
    if "permanent" in data_loss:
        return 4
    if not reversible and entry.get("time_window_hours", 1) == 0 and not automated:
        # rollback exists in name only, not automated, and no time window
        if risk in ("high", "critical"):
            return 4

    # Tier 3: Data loss or very hard to recover
    if not reversible and risk == "high":
        return 3
    if data_loss not in ("none", "") and "config" not in data_loss and "session" not in data_loss:
        # Real data loss: files, credentials, databases, etc.
        if "file" in data_loss or "data" in data_loss or "account" in data_loss or "destroy" in data_loss:
            return 3
    if downtime > 120:
        return 3

    # Tier 2: Requires manual intervention or causes significant disruption
    if not reversible and risk == "medium":
        return 2
    if not automated and risk in ("medium", "high"):
        return 2
    if downtime >= 10 and not automated:
        return 2
    if risk == "high":
        return 2

    # Tier 1: Trivial — 1-click undo, no side effects
    return 1


# ── Catalog action_types missing from DB ─────────────────────────────────────
# These are the 49 action_catalog entries with their canonical DB-compatible names.
# For each one missing from the DB, we inject it with correct tier.

CATALOG_MISSING_ENTRIES = [
    # Network
    {"action_type": "network_block",        "category": "network",    "reversible": True,  "requires_backup": False, "rollback_method": "network_unblock", "rollback_command": "Remove firewall block rule", "rollback_automated": True,  "time_window_hours": 24,  "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "network_unblock",      "category": "network",    "reversible": True,  "requires_backup": False, "rollback_method": "network_block",   "rollback_command": "Re-apply block rule",       "rollback_automated": True,  "time_window_hours": 24,  "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "firewall_rule_add",    "category": "network",    "reversible": True,  "requires_backup": False, "rollback_method": "firewall_rule_remove","rollback_command": "Remove added firewall rule","rollback_automated": True,"time_window_hours": 168, "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "firewall_rule_remove", "category": "network",    "reversible": True,  "requires_backup": True,  "rollback_method": "firewall_rule_add", "rollback_command": "Re-add removed rule",       "rollback_automated": True,  "time_window_hours": 168, "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk": "configuration","estimated_downtime_minutes": 0},
    {"action_type": "network_rejoin",       "category": "network",    "reversible": True,  "requires_backup": False, "rollback_method": "network_isolate",  "rollback_command": "Re-isolate segment",        "rollback_automated": False, "time_window_hours": 24,  "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 5},
    {"action_type": "port_block",           "category": "network",    "reversible": True,  "requires_backup": False, "rollback_method": "port_unblock",     "rollback_command": "Remove port block rule",    "rollback_automated": True,  "time_window_hours": 24,  "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "host_based_firewall_rule","category":"network",  "reversible": True,  "requires_backup": False, "rollback_method": "host_based_firewall_rule_remove","rollback_command":"Remove OS-level firewall rule","rollback_automated":False,"time_window_hours":168,"risk_category":"medium","prerequisites_for_rollback":[],"data_loss_risk":"none","estimated_downtime_minutes":0},
    {"action_type": "cloud_waf_block",      "category": "network",    "reversible": True,  "requires_backup": False, "rollback_method": "cloud_waf_unblock","rollback_command": "Remove WAF rule",           "rollback_automated": True,  "time_window_hours": 48,  "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "cloud_security_group_update","category":"network","reversible":True,  "requires_backup": True,  "rollback_method": "cloud_security_group_restore","rollback_command":"Restore prior security group config","rollback_automated":False,"time_window_hours":48,"risk_category":"medium","prerequisites_for_rollback":["backup_exists"],"data_loss_risk":"configuration","estimated_downtime_minutes":5},
    # Endpoint
    {"action_type": "endpoint_isolate",     "category": "endpoint",   "reversible": True,  "requires_backup": False, "rollback_method": "endpoint_rejoin",  "rollback_command": "EDR console: unisolate host","rollback_automated": False,"time_window_hours": 48,  "risk_category": "high",   "prerequisites_for_rollback": ["verify_system_clean"], "data_loss_risk": "none","estimated_downtime_minutes": 60},
    {"action_type": "endpoint_rejoin",      "category": "endpoint",   "reversible": True,  "requires_backup": False, "rollback_method": "endpoint_isolate", "rollback_command": "EDR console: re-isolate",   "rollback_automated": True,  "time_window_hours": 24,  "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "registry_block",       "category": "endpoint",   "reversible": True,  "requires_backup": True,  "rollback_method": "registry_unblock", "rollback_command": "Remove registry block policy","rollback_automated":False,"time_window_hours":168,  "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "run_edr_scan",         "category": "endpoint",   "reversible": True,  "requires_backup": False, "rollback_method": "cancel_scan",      "rollback_command": "Cancel EDR scan",           "rollback_automated": True,  "time_window_hours": 2,   "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 5},
    {"action_type": "patch_vulnerability",  "category": "endpoint",   "reversible": False, "requires_backup": True,  "rollback_method": "rollback_patch",   "rollback_command": "Restore pre-patch snapshot", "rollback_automated":False, "time_window_hours": 48,  "risk_category": "medium", "prerequisites_for_rollback": ["backup_exists"], "data_loss_risk":"configuration","estimated_downtime_minutes":30},
    {"action_type": "application_block",    "category": "endpoint",   "reversible": True,  "requires_backup": False, "rollback_method": "application_unblock","rollback_command":"Remove AppLocker/WDAC rule","rollback_automated":False,"time_window_hours":168,  "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "deception_token_plant","category": "endpoint",   "reversible": True,  "requires_backup": False, "rollback_method": "deception_token_remove","rollback_command":"Remove decoy file/credential","rollback_automated":True,"time_window_hours":720, "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "container_kill",       "category": "container",  "reversible": False, "requires_backup": False, "rollback_method": "redeploy_container","rollback_command":"Re-deploy from container image","rollback_automated":False,"time_window_hours":0,  "risk_category": "high",   "prerequisites_for_rollback": ["image_available"], "data_loss_risk":"container_state_and_data","estimated_downtime_minutes":30},
    # Identity
    {"action_type": "disable_user",         "category": "identity",   "reversible": True,  "requires_backup": False, "rollback_method": "enable_user",     "rollback_command": "Enable user account in IAM", "rollback_automated": True,  "time_window_hours": 720, "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "enable_user",          "category": "identity",   "reversible": True,  "requires_backup": False, "rollback_method": "disable_user",    "rollback_command": "Disable user again",         "rollback_automated": True,  "time_window_hours": 720, "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "unlock_account",       "category": "identity",   "reversible": True,  "requires_backup": False, "rollback_method": "lock_account",    "rollback_command": "Re-lock account if needed",  "rollback_automated": True,  "time_window_hours": 24,  "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "revoke_session",       "category": "identity",   "reversible": True,  "requires_backup": False, "rollback_method": "allow_relogin",   "rollback_command": "User re-authenticates normally","rollback_automated":True,"time_window_hours":1,   "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "unsaved_session_data","estimated_downtime_minutes":0},
    {"action_type": "mfa_enforce",          "category": "identity",   "reversible": True,  "requires_backup": False, "rollback_method": "mfa_remove",      "rollback_command": "Remove MFA policy from user", "rollback_automated": True,  "time_window_hours": 720, "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "revoke_iam_role",      "category": "identity",   "reversible": True,  "requires_backup": True,  "rollback_method": "restore_iam_role","rollback_command": "Restore IAM role from backup","rollback_automated":False,"time_window_hours":168, "risk_category": "high",   "prerequisites_for_rollback": ["backup_exists"], "data_loss_risk":"configuration","estimated_downtime_minutes":0},
    {"action_type": "restore_iam_role",     "category": "identity",   "reversible": True,  "requires_backup": False, "rollback_method": "revoke_iam_role", "rollback_command": "Revoke the restored role",   "rollback_automated": True,  "time_window_hours": 168, "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "vpn_disconnect",       "category": "identity",   "reversible": True,  "requires_backup": False, "rollback_method": "allow_vpn_reconnect","rollback_command":"User reconnects VPN",       "rollback_automated": True,  "time_window_hours": 1,   "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    # Email
    {"action_type": "block_email",          "category": "email",      "reversible": True,  "requires_backup": False, "rollback_method": "allow_email",     "rollback_command": "Remove sender block rule",   "rollback_automated": True,  "time_window_hours": 720, "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "quarantine_email",     "category": "email",      "reversible": True,  "requires_backup": False, "rollback_method": "release_quarantine_email","rollback_command":"Move email back to inbox","rollback_automated":True,"time_window_hours":720, "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    # Forensic
    {"action_type": "collect_logs",         "category": "forensics",  "reversible": True,  "requires_backup": False, "rollback_method": "delete_collected_logs","rollback_command":"Delete log archive",      "rollback_automated": True,  "time_window_hours": 720, "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "collect_memory_dump",  "category": "forensics",  "reversible": True,  "requires_backup": False, "rollback_method": "delete_dump",     "rollback_command": "Delete memory dump file",    "rollback_automated": True,  "time_window_hours": 720, "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 5},
    {"action_type": "snapshot_disk",        "category": "forensics",  "reversible": True,  "requires_backup": False, "rollback_method": "delete_snapshot", "rollback_command": "Delete disk snapshot",       "rollback_automated": True,  "time_window_hours": 720, "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    # Cloud
    {"action_type": "stop_instance",        "category": "cloud_compute","reversible":True, "requires_backup": False, "rollback_method": "start_instance",  "rollback_command": "Start VM instance",          "rollback_automated": True,  "time_window_hours": 168, "risk_category": "high",   "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 60},
    {"action_type": "start_instance",       "category": "cloud_compute","reversible":True, "requires_backup": False, "rollback_method": "stop_instance",   "rollback_command": "Stop VM instance",           "rollback_automated": True,  "time_window_hours": 168, "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "block_s3_access",      "category": "cloud_storage","reversible":True, "requires_backup": False, "rollback_method": "restore_s3_access","rollback_command":"Restore S3 bucket policy",   "rollback_automated": False, "time_window_hours": 168, "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "rotate_secret",        "category": "cloud_multi", "reversible": False,"requires_backup": False, "rollback_method": "issue_new_secret","rollback_command": "Rotate to new secret again","rollback_automated":False, "time_window_hours": 0,   "risk_category": "medium", "prerequisites_for_rollback": [], "data_loss_risk":"old_secret_invalidated","estimated_downtime_minutes":15},
    {"action_type": "revoke_cloud_credentials","category":"cloud_iam","reversible":False,  "requires_backup": False, "rollback_method": "issue_new_credentials","rollback_command":"Issue new temporary credentials","rollback_automated":True,"time_window_hours":0, "risk_category":"low",    "prerequisites_for_rollback": [], "data_loss_risk": "old_token_invalidated","estimated_downtime_minutes":0},
    {"action_type": "lambda_disable",       "category": "cloud_multi", "reversible": True,  "requires_backup": False, "rollback_method": "lambda_enable",   "rollback_command": "Re-enable serverless function","rollback_automated":True,"time_window_hours":24,  "risk_category": "high",   "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 5},
    {"action_type": "lambda_enable",        "category": "cloud_multi", "reversible": True,  "requires_backup": False, "rollback_method": "lambda_disable",  "rollback_command": "Disable function again",     "rollback_automated": True,  "time_window_hours": 24,  "risk_category": "low",    "prerequisites_for_rollback": [], "data_loss_risk": "none",         "estimated_downtime_minutes": 0},
    {"action_type": "certificate_revoke",   "category": "cloud_multi", "reversible": False, "requires_backup": False, "rollback_method": "reissue_certificate","rollback_command":"Issue new certificate from CA","rollback_automated":False,"time_window_hours":0,  "risk_category": "high",   "prerequisites_for_rollback": ["ca_access"], "data_loss_risk":"old_certificate_invalidated","estimated_downtime_minutes":120},
]


def main():
    db_path = os.path.normpath(os.path.join(os.path.dirname(__file__), DB_PATH))
    print(f"Loading: {db_path}")

    with open(db_path, encoding="utf-8") as f:
        db: list = json.load(f)

    original_count = len(db)
    existing_types = {entry["action_type"] for entry in db}

    # Step 1: Add reversibility_tier to all existing entries
    tier_added = 0
    for entry in db:
        if "reversibility_tier" not in entry:
            entry["reversibility_tier"] = compute_tier(entry)
            tier_added += 1

    # Step 2: Merge missing catalog entries
    injected = 0
    for entry in CATALOG_MISSING_ENTRIES:
        if entry["action_type"] not in existing_types:
            entry["reversibility_tier"] = compute_tier(entry)
            db.append(entry)
            existing_types.add(entry["action_type"])
            injected += 1

    # Step 3: Re-sort by category then action_type for readability
    db.sort(key=lambda x: (x.get("category", ""), x.get("action_type", "")))

    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)

    # Stats
    from collections import Counter
    tiers = Counter(e["reversibility_tier"] for e in db)
    print(f"Original entries    : {original_count}")
    print(f"Tier fields added   : {tier_added}")
    print(f"New entries injected: {injected}")
    print(f"Final total         : {len(db)}")
    print(f"Tier distribution   : {dict(sorted(tiers.items()))}")

    # Validate: all entries have tier
    missing = [e["action_type"] for e in db if "reversibility_tier" not in e]
    if missing:
        print(f"WARNING: missing tier: {missing}")
    else:
        print("All entries have reversibility_tier ✓")


if __name__ == "__main__":
    main()
