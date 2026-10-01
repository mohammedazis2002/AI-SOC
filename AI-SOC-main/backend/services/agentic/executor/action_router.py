"""
Action Router
=============
Routes remediation actions to the appropriate integration client.
Each client is a stub — real implementation requires SIEM/platform credentials.
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


# ── Client stubs ──────────────────────────────────────────────────────────────

class FirewallClient:
    """Palo Alto / AWS SG / iptables."""
    async def execute(self, action: Dict) -> Dict:
        logger.info(f"[Firewall] {action['type']} → {action['target']}")
        # TODO: implement real API call
        return {"status": "ok", "client": "FirewallClient"}


class EDRClient:
    """SentinelOne / Wazuh Active Response / CrowdStrike."""
    async def execute(self, action: Dict) -> Dict:
        logger.info(f"[EDR] {action['type']} → {action['target']}")
        return {"status": "ok", "client": "EDRClient"}


class IAMClient:
    """Active Directory / Azure AD / Okta."""
    async def execute(self, action: Dict) -> Dict:
        logger.info(f"[IAM] {action['type']} → {action['target']}")
        return {"status": "ok", "client": "IAMClient"}


class EmailGWClient:
    """O365 / Google Workspace."""
    async def execute(self, action: Dict) -> Dict:
        logger.info(f"[Email] {action['type']} → {action['target']}")
        return {"status": "ok", "client": "EmailGWClient"}


class CloudClient:
    """AWS / Azure / GCP."""
    async def execute(self, action: Dict) -> Dict:
        logger.info(f"[Cloud] {action['type']} → {action['target']}")
        return {"status": "ok", "client": "CloudClient"}


class ManualClient:
    """Fallback for unknown action types — logs and requires human intervention."""
    async def execute(self, action: Dict) -> Dict:
        logger.warning(f"[Manual] Unsupported action: {action['type']} — human intervention required")
        raise NotImplementedError(f"No client for action type '{action['type']}'")


# ── Action → Client mapping ───────────────────────────────────────────────────

_CLIENT_MAP: Dict[str, Any] = {
    # Network
    "network_block":          FirewallClient,
    "network_unblock":        FirewallClient,
    "rate_limit":              FirewallClient,
    "firewall_rule_add":       FirewallClient,
    "network_isolate":         FirewallClient,
    "network_rejoin":          FirewallClient,
    "dns_sinkhole":            FirewallClient,
    "block_dns_query":         FirewallClient,
    "allow_dns_query":         FirewallClient,
    "remove_rate_limit":       FirewallClient,
    "firewall_rule_remove":    FirewallClient,
    "remove_dns_sinkhole":     FirewallClient,

    # Endpoint
    "endpoint_isolate":        EDRClient,
    "endpoint_rejoin":         EDRClient,
    "kill_process":            EDRClient,
    "quarantine_file":         EDRClient,
    "restore_quarantine_file": EDRClient,
    "delete_file":             EDRClient,
    "registry_block":          EDRClient,
    "registry_unblock":        EDRClient,
    "run_edr_scan":            EDRClient,
    "patch_vulnerability":     EDRClient,
    "collect_logs":            EDRClient,
    "collect_memory_dump":     EDRClient,
    "snapshot_disk":           EDRClient,

    # Identity / IAM
    "disable_user":            IAMClient,
    "enable_user":             IAMClient,
    "lock_account":            IAMClient,
    "unlock_account":          IAMClient,
    "reset_password":          IAMClient,
    "revoke_session":          IAMClient,
    "mfa_enforce":             IAMClient,
    "mfa_remove":              IAMClient,
    "revoke_iam_role":         IAMClient,
    "restore_iam_role":        IAMClient,

    # Email
    "block_email":             EmailGWClient,
    "allow_email":             EmailGWClient,
    "quarantine_email":        EmailGWClient,
    "release_quarantine_email":EmailGWClient,

    # Cloud
    "stop_instance":           CloudClient,
    "start_instance":          CloudClient,
    "block_s3_access":         CloudClient,
    "restore_s3_access":       CloudClient,
    "rotate_secret":           CloudClient,
    "revoke_cloud_credentials":CloudClient,
}

# Singleton instances
_INSTANCES: Dict[str, Any] = {}


def get_action_client(action_type: str) -> Any:
    """Return the appropriate client instance for the given action type."""
    cls = _CLIENT_MAP.get(action_type, ManualClient)
    if cls not in _INSTANCES:
        _INSTANCES[cls] = cls()
    return _INSTANCES[cls]


class ActionRouter:
    """Routes an action dict to the correct client and executes it."""

    def __init__(self, db=None):
        self._db = db

    async def dispatch(self, action: Dict[str, Any], alert: Dict[str, Any]) -> Dict:
        """Dispatch action to correct client. Raises exception on failure."""
        action_type = action.get("type", "")
        client = get_action_client(action_type)

        # Inject alert context the client might need
        enriched_action = {
            **action,
            "_incident_context": {
                "src_ip":   (alert.get("src_endpoint") or {}).get("ip"),
                "hostname": (alert.get("src_endpoint") or {}).get("hostname"),
                "severity": alert.get("severity"),
            },
        }
        result = await client.execute(enriched_action)
        return result
