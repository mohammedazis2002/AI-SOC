"""
Blast Radius Tool
=================
Estimates the impact of executing a proposed remediation plan:
  - unique_impacted_assets  (hostnames / asset IDs)
  - users_affected          (deduplicated canonical user accounts)

Entity Resolution — Waterfall Target Classifier
------------------------------------------------
Every remediation action carries a "target" field.  That value can be:

  IP address        10.0.0.5
  IP range/CIDR     10.0.0.0/24
  Hostname          laptop-jdoe / server-01.acme.com (FQDN)
  Email             jdoe@acme.com
  Username          jdoe
  Domain prefix     ACME\\jdoe
  MAC address       aa:bb:cc:dd:ee:ff
  Cloud resource    i-0abc1234 / arn:aws:... / /subscriptions/.../...
  Container/Pod     pod-jdoe-abc123 / k8s:mynamespace/mypod
  Session token     sub:jdoe@acme.com
  File / path       /tmp/malware.sh  (no user impact)
  Process / PID     svchost.exe / 1234  (no direct user impact)

The classifier runs the target string through a priority-ordered chain of
regex matchers and resolves it to a set of canonical usernames.

All resolved users are added to a Python set().  users_affected = len(set).

This means: jdoe@acme.com + 10.0.0.5 (jdoe's laptop) = 1 user, not 2.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ── Regex patterns — ordered by specificity ───────────────────────────────────

_RE_IPv4            = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_RE_CIDR            = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_RE_MAC             = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
_RE_EMAIL           = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_DOMAIN_USER     = re.compile(r"^[A-Za-z0-9_\-]+\\[A-Za-z0-9_\-\.@]+$")   # DOMAIN\user
_RE_AWS_ARN         = re.compile(r"^arn:[a-z]+:[a-z0-9\-]+:")
_RE_AWS_INSTANCE    = re.compile(r"^i-[0-9a-f]{8,17}$")
_RE_AZURE_RES       = re.compile(r"^/subscriptions/[^/]+/")
_RE_K8S             = re.compile(r"^k8s:[^/]+/[^/]+$")
_RE_CONTAINER       = re.compile(r"^(pod|container|docker)-[a-zA-Z0-9_\-]+$", re.IGNORECASE)
_RE_SESSION_TOKEN   = re.compile(r"^sub:(.+)$", re.IGNORECASE)
_RE_FILE_PATH       = re.compile(r"^(/|[A-Za-z]:\\|~/).*$")
_RE_PID             = re.compile(r"^\d{1,6}$")
_RE_FQDN            = re.compile(r"^[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+$")     # Contains dots, not an IP

# Identity action types — target is a human account identifier
_IDENTITY_ACTIONS = frozenset({
    "disable_user", "enable_user", "lock_account", "unlock_account",
    "reset_password", "disable_account",
    "revoke_session", "mfa_enforce", "revoke_iam_role", "restore_iam_role",
    "vpn_disconnect", "force_logout", "force_logout_all_sessions",
    "expire_password", "revoke_admin_rights", "downgrade_privileges",
    "revoke_api_token", "revoke_oauth_token", "revoke_ssh_key",
    "revoke_kerberos_ticket", "rotate_service_account_key",
    "revoke_permissions", "enable_mfa",
})

# Host/endpoint action types — target is a machine, may have users on it
_HOST_ACTIONS = frozenset({
    "endpoint_isolate", "endpoint_rejoin", "stop_instance", "start_instance",
    "kill_process", "kill_process_tree", "suspend_process",
    "quarantine_file", "delete_file", "shred_file",
    "run_edr_scan", "trigger_edr_isolate", "trigger_edr_scan",
    "collect_memory_dump", "collect_logs", "snapshot_disk", "capture_memory_dump",
    "patch_vulnerability", "registry_block", "application_block",
    "service_disable", "scheduled_task_remove", "container_kill",
    "deception_token_plant", "host_based_firewall_rule",
    "reboot_system", "shutdown_system", "enable_safe_mode",
    "block_usb_devices", "enable_application_whitelisting",
    "restore_system_snapshot",
})


# ── Public API ────────────────────────────────────────────────────────────────

def calculate_blast_radius(
    actions: List[Dict[str, Any]],
    db=None,
) -> Dict[str, Any]:
    """
    Calculate blast radius of a remediation plan.

    Args:
        actions: List of remediation actions (after enrich_actions())
        db:      PyMongo database handle.  If None, heuristic mode.

    Returns:
        unique_impacted_assets  int
        impacted_asset_ids      List[str]
        users_affected          int    ← entity-resolved, deduplicated
        resolved_user_names     List[str]
        breakdown               Dict[str, List[str]]
        estimation_mode         "exact" | "estimated"
    """
    all_assets: Set[str]  = set()
    breakdown: Dict[str, List[str]] = {}

    for action in actions:
        atype  = action.get("type", "")
        target = action.get("target", "")
        hit    = _lookup_impacted_assets(atype, target, db)
        breakdown[f"{atype}:{target}"] = hit
        all_assets.update(hit)

    resolved_users = _resolve_all_users(actions, db)

    mode = "exact" if db is not None else "estimated"
    logger.info(
        f"Blast radius: {len(all_assets)} assets, {len(resolved_users)} users "
        f"[{len(actions)} actions, {mode}]"
    )

    return {
        "unique_impacted_assets": len(all_assets),
        "impacted_asset_ids":     list(all_assets),
        "users_affected":         len(resolved_users),
        "resolved_user_names":    list(resolved_users),
        "breakdown":              breakdown,
        "estimation_mode":        mode,
    }


# ── Waterfall Entity Resolver ─────────────────────────────────────────────────

def _resolve_all_users(actions: List[Dict], db) -> Set[str]:
    """
    For every action, classify the target type and resolve to canonical usernames.
    All usernames go into one set — deduplication is automatic.
    """
    resolved: Set[str] = set()
    for action in actions:
        atype  = action.get("type", "")
        target = (action.get("target") or "").strip()
        if not target:
            continue
        users = _resolve_target_to_users(target, atype, db)
        resolved.update(users)
    return resolved


def _resolve_target_to_users(target: str, action_type: str, db) -> Set[str]:
    """
    Waterfall classifier: run the target through regex matchers in priority order
    and return all canonical usernames associated with that target.

    Priority order (highest specificity first):
      1. Session token  (sub:user)          → extract subject → user lookup
      2. MAC address                         → asset lookup → accessed_by_users
      3. AWS ARN / resource                  → no user (cloud resource)
      4. Azure resource ID                   → no user
      5. K8s pod ref  (k8s:ns/pod)           → hostname lookup → accessed_by_users
      6. Container name                      → hostname lookup → accessed_by_users
      7. AWS instance ID (i-xxx)             → asset tag lookup → accessed_by_users
      8. CIDR range                          → subnet scan → all asset users
      9. IPv4 address                        → asset IP lookup → accessed_by_users
     10. Email address                       → user_inventory email → username
     11. DOMAIN\\user                         → extract sam account → username
     12. FQDN / hostname with dots           → asset hostname lookup → accessed_by_users
     13. Identity action + short string      → treat as username directly
     14. Anything else (file, PID, process)  → no user impact
    """
    t = target.strip()

    # 1. Session token (sub:jdoe@acme.com)
    m = _RE_SESSION_TOKEN.match(t)
    if m:
        subject = m.group(1)
        return _resolve_target_to_users(subject, action_type, db)

    # 2. MAC address → asset lookup
    if _RE_MAC.match(t):
        return _users_from_asset_query({"mac_address": t}, db)

    # 3. AWS ARN (resource, not a user)
    if _RE_AWS_ARN.match(t):
        return set()   # Cloud resource — no direct user

    # 4. Azure resource ID
    if _RE_AZURE_RES.match(t):
        return set()

    # 5. Kubernetes pod reference  k8s:namespace/podname
    if _RE_K8S.match(t):
        pod_part = t.split(":", 1)[-1].split("/")[-1]
        return _users_from_asset_query({"hostname": pod_part}, db)

    # 6. Container name
    if _RE_CONTAINER.match(t):
        return _users_from_asset_query({"hostname": t}, db)

    # 7. AWS instance ID  i-0abc1234
    if _RE_AWS_INSTANCE.match(t):
        return _users_from_asset_query({"tags.instance_id": t}, db)

    # 8. CIDR range → resolve all assets in that subnet
    if _RE_CIDR.match(t):
        return _users_from_asset_query({"network_segment": t}, db)

    # 9. IPv4 address
    if _RE_IPv4.match(t):
        return _users_from_asset_query({"ip_addresses": t}, db)

    # 10. Email address → user_inventory lookup
    if _RE_EMAIL.match(t):
        return _resolve_email(t, db)

    # 11. DOMAIN\user → extract sam account name
    if _RE_DOMAIN_USER.match(t):
        sam = t.split("\\", 1)[-1].lower()
        return {sam}

    # 12. FQDN or hostname with dots (not an IP — already handled)
    if _RE_FQDN.match(t):
        return _users_from_asset_query({"hostname": t}, db)

    # 13. Identity action + short string (no dots, no @) → treat as username
    if action_type in _IDENTITY_ACTIONS:
        canonical = t.lower().split("\\")[-1].split("@")[0]
        return {canonical} if canonical else set()

    # 14. Short string + host action → hostname lookup
    if action_type in _HOST_ACTIONS and t:
        result = _users_from_asset_query({"hostname": t}, db)
        return result if result else set()

    # 15. Everything else (file path, PID, process name) → no user impact
    return set()


def _resolve_email(email: str, db) -> Set[str]:
    """Resolve an email to canonical username via user_inventory, or return normalised email prefix."""
    if db is None:
        return {email.lower().split("@")[0]}
    try:
        doc = db.user_inventory.find_one(
            {"$or": [{"email": email}, {"email": email.lower()}]},
            {"username": 1},
        )
        if doc and doc.get("username"):
            return {doc["username"].lower()}
        # Not in inventory — use email prefix as best guess
        return {email.lower().split("@")[0]}
    except Exception as e:
        logger.warning(f"user_inventory lookup failed for {email}: {e}")
        return {email.lower().split("@")[0]}


def _users_from_asset_query(query: dict, db) -> Set[str]:
    """Query asset_inventory with 'query', return the union of all accessed_by_users."""
    if db is None:
        return set()
    try:
        users: Set[str] = set()
        for doc in db.asset_inventory.find(query, {"accessed_by_users": 1}):
            for u in (doc.get("accessed_by_users") or []):
                if u:
                    users.add(u.lower())
        return users
    except Exception as e:
        logger.warning(f"asset_inventory lookup failed ({query}): {e}")
        return set()


# ── Asset Lookup (unchanged from previous version) ────────────────────────────

def _lookup_impacted_assets(action_type: str, target: str, db) -> List[str]:
    if not target:
        return []
    if db is None:
        return _heuristic_estimate(action_type, target)

    assets   = db.asset_inventory
    impacted: Set[str] = set()

    try:
        if action_type in ("network_block", "dns_sinkhole", "block_dns_query",
                           "block_ip", "block_domain", "null_route_ip"):
            for doc in assets.find({"connected_to": target}, {"asset_id": 1}):
                impacted.add(doc["asset_id"])

        elif action_type in ("network_isolate", "isolate_network_segment"):
            for doc in assets.find({"network_segment": target}, {"asset_id": 1}):
                impacted.add(doc["asset_id"])

        elif action_type in ("endpoint_isolate", "stop_instance", "endpoint_rejoin",
                             "isolate_host", "trigger_edr_isolate", "shutdown_system",
                             "reboot_system"):
            impacted.add(target)
            for doc in assets.find({"depends_on": target}, {"asset_id": 1}):
                impacted.add(doc["asset_id"])

        elif action_type in _IDENTITY_ACTIONS:
            username = target.lower().split("\\")[-1].split("@")[0]
            for doc in assets.find({"accessed_by_users": username}, {"asset_id": 1}):
                impacted.add(doc["asset_id"])

        elif action_type in _HOST_ACTIONS:
            impacted.add(target)

        elif action_type in ("block_s3_access", "rotate_secret",
                             "revoke_cloud_credentials", "lambda_disable"):
            impacted.add(target)

    except Exception as e:
        logger.warning(f"Blast radius asset query failed [{action_type}:{target}]: {e}")
        return _heuristic_estimate(action_type, target)

    return list(impacted)


def _heuristic_estimate(action_type: str, target: str) -> List[str]:
    HIGH_SCOPE = {"network_isolate", "endpoint_isolate", "disable_user",
                  "stop_instance", "isolate_host"}
    MED_SCOPE  = {"network_block", "firewall_rule_add", "revoke_iam_role",
                  "block_s3_access", "lock_account"}
    if action_type in HIGH_SCOPE:
        return [f"{target}:est:{i}" for i in range(10)]
    elif action_type in MED_SCOPE:
        return [f"{target}:est:{i}" for i in range(3)]
    return [f"{target}:est:0"]
