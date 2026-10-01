"""
Executor — Auto-Execute Remediation Actions
===========================================
Called by Decision Engine when decision = AUTO_EXECUTE.
NOT a LangGraph node — called inline from the Decision Engine execute().

Execution strategy:
  - Ordered by action.execution_order (forensic → reversible+low-risk → irreversible+high-risk)
  - Per action: 3 attempts with exponential backoff (2s, 4s, 8s)
  - If all 3 attempts fail:
      a. If action is reversible → rollback all completed actions
      b. Escalate to L2 with execution_failure_bundle
      c. STOP (do not continue to next action)
  - If dependent action follows a failed action → STOP + rollback + escalate

All actions written to MongoDB actions_log.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from .action_router import ActionRouter, get_action_client
from ..tools.mongodb_helper import mongodb_helper
from ..tools.redis_queue import redis_queue

logger = logging.getLogger(__name__)


class Executor:
    """Autonomous action executor with agentic retry, rollback, and escalation."""

    def __init__(self, db=None):
        self._db     = db
        self._router = ActionRouter(db=db)

    async def execute_plan(
        self,
        incident_id: str,
        remediation_plan: List[Dict[str, Any]],
        alert: Dict[str, Any],
        comprehensive_report: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute all actions in remediation_plan in order.

        Returns:
            {
                success:           bool,
                actions_executed:  List[dict],
                actions_failed:    List[dict],
                rollback_performed:bool,
                escalated:         bool,
                execution_summary: str,
            }
        """
        logger.info(f"[Executor] Starting execution: {incident_id} ({len(remediation_plan)} actions)")

        executed: List[Dict]  = []
        failed:   Optional[Dict] = None

        # Sort by execution_order (should already be sorted, but defensive)
        ordered_plan = sorted(
            remediation_plan,
            key=lambda a: a.get("execution_order", 99)
        )

        for action in ordered_plan:
            result = await self._execute_with_retry(action, alert, incident_id)

            if result["success"]:
                executed.append({**action, **result})
                await self._log_action(incident_id, action, result, "success")

            else:
                failed = {**action, **result}
                logger.error(
                    f"[Executor] Action FAILED after {result.get('attempts', 3)} attempts: "
                    f"{action.get('type')} on {action.get('target')}"
                )
                await self._log_action(incident_id, action, result, "failed")

                # Rollback completed actions if safe
                rollback_performed = False
                if executed:
                    rollback_performed = await self._rollback_completed(
                        executed, alert, incident_id
                    )

                # Escalate to L2
                await self._escalate_execution_failure(
                    incident_id, action, executed, result["error"],
                    comprehensive_report, rollback_performed
                )

                return {
                    "success":            False,
                    "actions_executed":   executed,
                    "actions_failed":     [failed],
                    "rollback_performed": rollback_performed,
                    "escalated":          True,
                    "execution_summary":  (
                        f"Stopped at action {action.get('execution_order')}/{len(ordered_plan)}: "
                        f"{action.get('type')} failed — {result['error']}"
                    ),
                }

        # All actions succeeded
        summary = (
            f"All {len(executed)} actions executed successfully for {incident_id}"
        )
        logger.info(f"[Executor] {summary}")

        return {
            "success":            True,
            "actions_executed":   executed,
            "actions_failed":     [],
            "rollback_performed": False,
            "escalated":          False,
            "execution_summary":  summary,
        }

    # ── Single action with retry ──────────────────────────────────────────────

    async def _execute_with_retry(
        self,
        action: Dict[str, Any],
        alert: Dict[str, Any],
        incident_id: str,
        max_attempts: int = 3,
    ) -> Dict[str, Any]:
        """
        Execute one action with up to max_attempts retries and exponential backoff.
        Returns result dict including success, attempts, and any error.
        """
        action_type = action.get("type", "")
        target      = action.get("target", "")
        last_error  = ""

        for attempt in range(1, max_attempts + 1):
            logger.info(
                f"[Executor] #{attempt} '{action_type}' on '{target}' (incident={incident_id})"
            )
            try:
                result = await self._router.dispatch(action, alert)
                return {
                    "success":   True,
                    "attempts":  attempt,
                    "result":    result,
                    "error":     "",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            except Exception as e:
                last_error = str(e)
                logger.warning(
                    f"[Executor] Attempt {attempt}/{max_attempts} failed: {e}"
                )
                if attempt < max_attempts:
                    wait = 2 ** attempt       # 2s, 4s, 8s
                    await asyncio.sleep(wait)

        return {
            "success":   False,
            "attempts":  max_attempts,
            "result":    {},
            "error":     last_error,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # ── Rollback ──────────────────────────────────────────────────────────────

    async def _rollback_completed(
        self,
        executed: List[Dict[str, Any]],
        alert: Dict[str, Any],
        incident_id: str,
    ) -> bool:
        """Roll back completed actions in reverse order (only if reversible)."""
        reversible = [a for a in executed if a.get("reversible", False)]
        if not reversible:
            logger.info("[Executor] No reversible actions to rollback")
            return False

        logger.info(f"[Executor] Rolling back {len(reversible)} reversible actions")
        rolled_back = 0

        for action in reversed(reversible):
            undo_type = action.get("undo_action") or f"undo_{action.get('type', '')}"
            undo_action = {**action, "type": undo_type, "rationale": "Rollback due to execution failure"}
            try:
                await self._router.dispatch(undo_action, alert)
                await self._log_action(incident_id, undo_action, {"success": True}, "rollback")
                rolled_back += 1
            except Exception as e:
                logger.error(f"[Executor] Rollback of {action.get('type')} failed: {e}")
                await self._log_action(incident_id, undo_action, {"success": False, "error": str(e)}, "rollback_failed")

        return rolled_back > 0

    # ── Escalation on execution failure ──────────────────────────────────────

    async def _escalate_execution_failure(
        self,
        incident_id: str,
        failed_action: Dict,
        executed_actions: List[Dict],
        error: str,
        report: Dict,
        rollback_performed: bool,
    ) -> None:
        bundle = {
            "incident_id":        incident_id,
            "escalation_type":    "execution_failure",
            "failed_action":      failed_action,
            "executed_actions":   executed_actions,
            "error":              error,
            "rollback_performed": rollback_performed,
            "original_report":    report,
            "escalated_at":       datetime.utcnow().isoformat(),
        }
        try:
            redis_queue.push_escalation(bundle, tier="l2")
        except Exception as e:
            logger.error(f"[Executor] Failed to push execution failure to Redis: {e}")

        try:
            mongodb_helper.save_incident({
                **bundle,
                "status":     "execution_failed_escalated",
                "created_at": datetime.utcnow(),
            })
        except Exception as e:
            logger.error(f"[Executor] MongoDB save failed: {e}")

    # ── Audit log ─────────────────────────────────────────────────────────────

    async def _log_action(
        self,
        incident_id: str,
        action: Dict,
        result: Dict,
        status: str,
    ) -> None:
        entry = {
            "incident_id":  incident_id,
            "action_type":  action.get("type"),
            "target":       action.get("target"),
            "status":       status,
            "attempts":     result.get("attempts", 1),
            "error":        result.get("error", ""),
            "timestamp":    datetime.utcnow(),
        }
        try:
            if self._db:
                self._db.actions_log.insert_one(entry)
        except Exception as e:
            logger.error(f"[Executor] Audit log write failed: {e}")
