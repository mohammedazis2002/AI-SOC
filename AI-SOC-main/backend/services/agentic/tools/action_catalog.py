"""
Action Catalog
==============
Single source of truth for actions the SOAR EXECUTOR can dispatch:
  client assignment, approval requirements, scope, and undo action.

action_type keys here are IDENTICAL to action_type keys in
reversibility_db_full.json.  That file is the single source of truth
for reversibility_tier (1-4), rollback commands, and risk metadata.

Do NOT hardcode risk levels or tiers here — always read from the DB
via services.agentic.tools.reversibility_lookup.get_reversibility_tier().

Execution order is assigned by assign_execution_order():
  Priority 1: category=forensic (evidence before destruction)
  Priority 2: Lower reversibility_tier first (safest action first)
  Priority 3: Narrowest impacted_scope first
"""

from typing import Dict, Any, List

ACTION_CATALOG: Dict[str, Dict[str, Any]] = {

    # ── Network ───────────────────────────────────────────────────────────────
    "block_ip": {
        "category":          "network",
        "description":       "Block traffic to/from a specific IP address",
        "undo_action":       "unblock_ip",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "FirewallClient",
    },
    "block_ip_range": {
        "category":          "network",
        "description":       "Block traffic to/from a CIDR range",
        "undo_action":       "unblock_ip_range",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "FirewallClient",
    },
    "block_domain": {
        "category":          "network",
        "description":       "DNS sinkhole or firewall block for a malicious domain",
        "undo_action":       "unblock_domain",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "FirewallClient",
    },
    "block_dns_query": {
        "category":          "network",
        "description":       "Block DNS queries for a specific domain (NXDOMAIN response)",
        "undo_action":       "unblock_dns_query",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "FirewallClient",
    },
    "block_url": {
        "category":          "network",
        "description":       "Block a specific URL at the proxy/WAF level",
        "undo_action":       "unblock_url",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "FirewallClient",
    },
    "rate_limit_ip": {
        "category":          "network",
        "description":       "Apply rate limiting to traffic from a specific IP",
        "undo_action":       "remove_rate_limit",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "FirewallClient",
    },
    "modify_firewall_rules": {
        "category":          "network",
        "description":       "Add or modify a firewall allow/deny rule",
        "undo_action":       "restore_firewall_rules",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "FirewallClient",
    },
    "isolate_network_segment": {
        "category":          "network",
        "description":       "Isolate an entire network segment by blocking all inter-segment traffic",
        "undo_action":       "restore_network_segment",
        "requires_approval": True,
        "impacted_scope":    "network-level",
        "client":            "FirewallClient",
    },
    "null_route_ip": {
        "category":          "network",
        "description":       "Black-hole route a specific IP (BGP/kernel null route)",
        "undo_action":       "remove_null_route",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "FirewallClient",
    },
    "block_port": {
        "category":          "network",
        "description":       "Block a specific TCP/UDP port on a host or perimeter firewall",
        "undo_action":       "unblock_port",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "FirewallClient",
    },
    "cloud_waf_block": {
        "category":          "network",
        "description":       "Add a WAF rule to block a specific IP, user-agent, or request pattern",
        "undo_action":       "cloud_waf_unblock",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "CloudClient",
    },
    "enable_ssl_inspection": {
        "category":          "network",
        "description":       "Enable SSL/TLS inspection on proxy or firewall",
        "undo_action":       "disable_ssl_inspection",
        "requires_approval": False,
        "impacted_scope":    "network-level",
        "client":            "FirewallClient",
    },
    "capture_network_traffic": {
        "category":          "network",
        "description":       "Start a packet capture (tcpdump/Zeek) for forensic analysis",
        "undo_action":       "stop_capture",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "EDRClient",
    },

    # ── Endpoint ──────────────────────────────────────────────────────────────
    "isolate_host": {
        "category":          "endpoint",
        "description":       "Isolate a host from the network via EDR containment",
        "undo_action":       "restore_network_connectivity",
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "trigger_edr_isolate": {
        "category":          "endpoint",
        "description":       "Trigger EDR-specific host isolation (vendor command)",
        "undo_action":       "lift_edr_isolation",
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "restore_network_connectivity": {
        "category":          "endpoint",
        "description":       "Remove EDR containment and restore full network access",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "kill_process": {
        "category":          "endpoint",
        "description":       "Terminate a running process by name or PID",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "EDRClient",
    },
    "kill_process_tree": {
        "category":          "endpoint",
        "description":       "Terminate a process and all its children",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "EDRClient",
    },
    "suspend_process": {
        "category":          "endpoint",
        "description":       "Suspend a running process (SIGSTOP / Windows suspend)",
        "undo_action":       "resume_process",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "EDRClient",
    },
    "quarantine_file": {
        "category":          "endpoint",
        "description":       "Move suspicious file to EDR quarantine vault (recoverable)",
        "undo_action":       "restore_from_quarantine",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "EDRClient",
    },
    "delete_file": {
        "category":          "endpoint",
        "description":       "Permanently delete a file from the filesystem",
        "undo_action":       "restore_from_backup",
        "requires_approval": True,
        "impacted_scope":    "targeted",
        "client":            "EDRClient",
    },
    "delete_registry_key": {
        "category":          "endpoint",
        "description":       "Remove a Windows registry key used for persistence",
        "undo_action":       "restore_registry_key",
        "requires_approval": False,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "trigger_edr_scan": {
        "category":          "endpoint",
        "description":       "Trigger a full AV/EDR scan on a host",
        "undo_action":       "cancel_scan",
        "requires_approval": False,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "patch_vulnerability": {
        "category":          "endpoint",
        "description":       "Apply OS or software patch to address a specific CVE",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "block_executable": {
        "category":          "endpoint",
        "description":       "Add an application/executable to the OS denylist (AppLocker/WDAC)",
        "undo_action":       "unblock_executable",
        "requires_approval": False,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "disable_service": {
        "category":          "endpoint",
        "description":       "Stop and disable a specific Windows/Linux service",
        "undo_action":       "enable_service",
        "requires_approval": False,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "scheduled_task_remove": {
        "category":          "endpoint",
        "description":       "Delete a scheduled task or cron job used for persistence",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "EDRClient",
    },
    "reboot_system": {
        "category":          "endpoint",
        "description":       "Reboot a host to clear in-memory malware or force patching",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "plant_honey_token": {
        "category":          "endpoint",
        "description":       "Plant a honey token / canary file or credential to detect attacker access",
        "undo_action":       "remove_honey_token",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "EDRClient",
    },
    "kill_container": {
        "category":          "endpoint",
        "description":       "Stop and remove a malicious or compromised container/pod",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "CloudClient",
    },

    # ── Identity / IAM ────────────────────────────────────────────────────────
    "disable_account": {
        "category":          "identity",
        "description":       "Disable a user account in AD/Azure AD/Okta — user cannot authenticate",
        "undo_action":       "enable_account",
        "requires_approval": True,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "enable_account": {
        "category":          "identity",
        "description":       "Re-enable a previously disabled user account",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "lock_account": {
        "category":          "identity",
        "description":       "Temporarily lock account (unlocks after TTL or manual unlock)",
        "undo_action":       "unlock_account",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "unlock_account": {
        "category":          "identity",
        "description":       "Unlock a temporarily locked account",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "reset_password": {
        "category":          "identity",
        "description":       "Force password reset — old credential immediately invalidated",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "expire_password": {
        "category":          "identity",
        "description":       "Expire a user's password forcing change at next login",
        "undo_action":       "remove_password_expiry",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "force_logout": {
        "category":          "identity",
        "description":       "Invalidate all active sessions — user re-authenticates on next request",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "enable_mfa": {
        "category":          "identity",
        "description":       "Force MFA enforcement for a specific user or group",
        "undo_action":       "disable_mfa",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "revoke_permissions": {
        "category":          "identity",
        "description":       "Remove an IAM role or permission set from a user/service account",
        "undo_action":       "restore_permissions",
        "requires_approval": True,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "revoke_api_token": {
        "category":          "identity",
        "description":       "Revoke an API key or OAuth token — re-issue required",
        "undo_action":       "issue_new_token",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "revoke_ssh_key": {
        "category":          "identity",
        "description":       "Remove an SSH public key from authorized_keys",
        "undo_action":       "restore_ssh_key",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },
    "vpn_disconnect": {
        "category":          "identity",
        "description":       "Force-terminate a user's active VPN session",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "IAMClient",
    },

    # ── Email / Communication ─────────────────────────────────────────────────
    "block_email_sender": {
        "category":          "email",
        "description":       "Block all incoming email from a specific sender address or domain",
        "undo_action":       "unblock_email_sender",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "EmailGWClient",
    },
    "quarantine_email": {
        "category":          "email",
        "description":       "Move specific email or thread to quarantine for investigation",
        "undo_action":       "release_quarantine_email",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "EmailGWClient",
    },

    # ── Forensic / Collection ─────────────────────────────────────────────────
    "collect_logs": {
        "category":          "forensic",
        "description":       "Collect and archive logs from host/service — read-only",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "capture_memory_dump": {
        "category":          "forensic",
        "description":       "Capture full memory image of process or host for forensic analysis",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },
    "snapshot_disk": {
        "category":          "forensic",
        "description":       "Create point-in-time disk snapshot for forensic preservation",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "host-level",
        "client":            "EDRClient",
    },

    # ── Cloud ─────────────────────────────────────────────────────────────────
    "stop_vm_instance": {
        "category":          "cloud",
        "description":       "Stop a cloud VM instance (EC2/Azure VM/GCP Compute)",
        "undo_action":       "start_vm_instance",
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "CloudClient",
    },
    "start_vm_instance": {
        "category":          "cloud",
        "description":       "Start a previously stopped cloud VM instance",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "CloudClient",
    },
    "block_s3_access": {
        "category":          "cloud",
        "description":       "Remove public or cross-account read access to an S3 bucket",
        "undo_action":       "restore_s3_access",
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "CloudClient",
    },
    "rotate_service_account_key": {
        "category":          "cloud",
        "description":       "Rotate a service account key, API key, or Secrets Manager secret",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "CloudClient",
    },
    "revoke_cloud_token": {
        "category":          "cloud",
        "description":       "Revoke a temporary cloud credential (AWS STS token, Azure access token)",
        "undo_action":       None,
        "requires_approval": False,
        "impacted_scope":    "targeted",
        "client":            "CloudClient",
    },
    "lambda_disable": {
        "category":          "cloud",
        "description":       "Disable a serverless function (Lambda/Azure Function/GCP Cloud Function)",
        "undo_action":       "lambda_enable",
        "requires_approval": True,
        "impacted_scope":    "targeted",
        "client":            "CloudClient",
    },
    "lambda_enable": {
        "category":          "cloud",
        "description":       "Re-enable a previously disabled serverless function",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "targeted",
        "client":            "CloudClient",
    },
    "revoke_certificate": {
        "category":          "cloud",
        "description":       "Revoke a TLS or code-signing certificate",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "targeted",
        "client":            "CloudClient",
    },
}

# ── Sort helpers ──────────────────────────────────────────────────────────────
_SCOPE_ORDER = {"targeted": 1, "host-level": 2, "network-level": 3, "org-level": 4}
_CATEGORY_ORDER = {
    "forensic": 0,   # Always first — preserve evidence before destroying
    "network":  1,
    "email":    2,
    "identity": 3,
    "endpoint": 4,
    "cloud":    5,
}

VALID_ACTION_TYPES = set(ACTION_CATALOG.keys())


def get_action_metadata(action_type: str) -> Dict[str, Any]:
    """Return catalog metadata for action_type. Falls back to conservative defaults."""
    return ACTION_CATALOG.get(action_type, {
        "category":          "unknown",
        "description":       f"Unknown action: {action_type}",
        "undo_action":       None,
        "requires_approval": True,
        "impacted_scope":    "host-level",
        "client":            "ManualClient",
    })


def enrich_actions(actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich LLM-generated actions with catalog metadata and assign execution_order.

    Tier and risk_level are NOT stored here — they are looked up from
    reversibility_db_full.json by reversibility_lookup.get_reversibility_tier().

    Sort order:
      1. Forensic first (evidence preservation)
      2. Narrowest scope first (targeted before host-level before network-level)
    """
    from backend.services.agentic.tools.reversibility_lookup import get_reversibility_tier

    def sort_key(a: Dict) -> tuple:
        meta = get_action_metadata(a.get("type", ""))
        tier = get_reversibility_tier(a.get("type", ""))
        return (
            _CATEGORY_ORDER.get(meta["category"], 99),
            tier,
            _SCOPE_ORDER.get(meta.get("impacted_scope", "host-level"), 99),
        )

    sorted_actions = sorted(actions, key=sort_key)

    for i, action in enumerate(sorted_actions):
        meta = get_action_metadata(action.get("type", ""))
        action["execution_order"]   = i + 1
        action.setdefault("requires_approval", meta["requires_approval"])
        action.setdefault("d3fend_control",    "")

    return sorted_actions


def get_max_risk_level(actions: List[Dict]) -> str:
    """Return the highest risk_level across all actions (reads from reversibility DB)."""
    from backend.services.agentic.tools.reversibility_lookup import get_db_entry
    _RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    levels = []
    for a in actions:
        entry = get_db_entry(a.get("type", ""))
        if entry:
            levels.append(_RISK_ORDER.get(entry.get("risk_category", "low"), 1))
    if not levels:
        return "low"
    inv = {v: k for k, v in _RISK_ORDER.items()}
    return inv.get(max(levels), "low")


def get_max_reversibility_tier(actions: List[Dict]) -> int:
    """Return the highest (worst) reversibility_tier across all actions."""
    from backend.services.agentic.tools.reversibility_lookup import get_reversibility_tier
    tiers = [get_reversibility_tier(a.get("type", "")) for a in actions]
    return max(tiers) if tiers else 1


def has_destructive_actions(actions: List[Dict]) -> bool:
    """True if any action is Tier 3 or Tier 4."""
    return get_max_reversibility_tier(actions) >= 3
