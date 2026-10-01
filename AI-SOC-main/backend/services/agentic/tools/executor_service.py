"""
Executor Service
================
Standalone service handling the execution of remediation plans.

Since the SOAR pipeline is strictly 4 nodes (Reasoning → Remediation → Auditor → Decision),
the Executor is NOT a LangGraph Node. Instead, it is invoked natively by the Decision Engine
when a final AUTO_EXECUTE decision is reached.

Features:
- Dispatches actions to abstract integration clients (Firewall, EDR, IAM, etc.)
- Strict rollback guard: if an action fails fatally (reversibility >= 3),
  execution is halted, an error is raised, and the Decision Engine demotes 
  the alert to MANUAL_REVIEW.
- Audit logging: Execution results appended to state for full observability.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

CLIENT_LABELS = {
    "FirewallClient":  "Firewall / WAF",
    "EDRClient":       "Endpoint Detection & Response",
    "IAMClient":       "Identity & Access Management",
    "EmailGWClient":   "Email Gateway",
    "SIEMClient":      "SIEM",
    "ThreatIntelClient": "Threat Intelligence Platform",
    "NetworkClient":   "Network Infrastructure",
    "CloudClient":     "Cloud Provider API",
    "DBClient":        "Database",
    "BackupClient":    "Backup System",
}

class RemediationExecutor:
    """Executes a remediation plan action by action."""

    async def execute_plan(self, plan: List[Dict[str, Any]], incident_id: str) -> List[Dict[str, Any]]:
        """
        Iterates through the plan in execution_order.
        Returns a list of execution receipts.
        Raises an Exception if a fatal failure occurs.
        """
        if not plan:
            logger.info(f"[{incident_id}] No actions in remediation plan to execute.")
            return []

        # Sort by execution_order if present
        ordered_plan = sorted(plan, key=lambda a: a.get("execution_order", 999))
        actions_executed: List[Dict[str, Any]] = []

        for action in ordered_plan:
            if action.get("status") == "already_executed":
                actions_executed.append({
                    **action,
                    "execution_result": "skipped",
                    "skip_reason":      "already_executed",
                    "executed_at":      datetime.now(timezone.utc).isoformat(),
                })
                continue

            result = await self._dispatch(action, incident_id)
            actions_executed.append(result)

            if result["execution_result"] == "failed" and result.get("fatal"):
                logger.error(
                    f"[{incident_id}] Fatal execution failure on action '{action.get('type')}': "
                    f"{result.get('error')} — aborting Remaining operations!"
                )
                raise Exception(f"Executor failed on {action.get('type')}: {result.get('error')}")

        return actions_executed

    async def _dispatch(self, action: Dict[str, Any], incident_id: str) -> Dict[str, Any]:
        """
        Map action to its integration client and call the stub.
        Phase 2 will replace these stubs with actual REST API calls to Crowdstrike, JumpCloud, etc.
        """
        action_type = action.get("type", "unknown")
        client_name = action.get("client", "UnknownClient")
        target      = action.get("target", "")
        label       = CLIENT_LABELS.get(client_name, client_name)

        logger.info(f"[{incident_id}] Dispatching: {action_type} → {label} (target={target!r})")

        base_record = {
            "type":            action_type,
            "target":          target,
            "client":          client_name,
            "phase":           action.get("phase", ""),
            "reversible":      action.get("reversible", True),
            "reversibility_tier": action.get("reversibility_tier", 1),
            "execution_order": action.get("execution_order", 0),
            "rationale":       action.get("rationale", ""),
            "executed_at":     datetime.now(timezone.utc).isoformat(),
            "executor":        "soar-autonomous-v1",
        }

        try:
            result = self._stub_call(client_name, action_type, target, incident_id)
            return {
                **base_record,
                "execution_result": "executed",
                "response":         result,
                "fatal":            False,
            }
        except Exception as e:
            is_fatal = action.get("reversibility_tier", 1) >= 3
            logger.error(f"[{incident_id}] Action {action_type} failed: {e} (fatal={is_fatal})")
            return {
                **base_record,
                "execution_result": "failed",
                "error":            str(e),
                "fatal":            is_fatal,
            }

    def _stub_call(self, client: str, action_type: str, target: str, incident_id: str) -> Dict:
        """
        Stub integration dispatcher. Real API logic will be wired here later.
        """
        if client == "FirewallClient":
            logger.info(f"[STUB] FirewallClient.{action_type}(target={target}, incident={incident_id})")
            return {"status": "simulated_ok", "firewall_rule_id": f"fw-{incident_id[:8]}"}

        elif client == "EDRClient":
            logger.info(f"[STUB] EDRClient.{action_type}(target={target}, incident={incident_id})")
            return {"status": "simulated_ok", "edr_job_id": f"edr-{incident_id[:8]}"}

        elif client == "IAMClient":
            logger.info(f"[STUB] IAMClient.{action_type}(target={target}, incident={incident_id})")
            return {"status": "simulated_ok", "iam_ticket": f"iam-{incident_id[:8]}"}

        elif client == "EmailGWClient":
            logger.info(f"[STUB] EmailGWClient.{action_type}(target={target}, incident={incident_id})")
            return {"status": "simulated_ok", "email_quarantine_id": f"emq-{incident_id[:8]}"}

        elif client == "SIEMClient":
            logger.info(f"[STUB] SIEMClient.{action_type}(target={target}, incident={incident_id})")
            return {"status": "simulated_ok", "siem_rule_id": f"siem-{incident_id[:8]}"}

        else:
            logger.warning(f"[STUB] Unknown client '{client}' for {action_type}. Logging only.")
            return {"status": "unknown_client_logged_only"}

# Global singleton
executor_service = RemediationExecutor()
