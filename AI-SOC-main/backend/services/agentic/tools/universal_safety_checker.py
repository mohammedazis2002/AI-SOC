"""
Universal Safety Checker — Layer 0 of the Auditor Agent
========================================================
Checks remediation plan actions against 7 Universal Safety Rules.

These rules fire UNCONDITIONALLY for ALL assets — no compliance scope,
no context gate, no AI confidence threshold can bypass them.
They are the first check in the auditor pipeline.

Rules:
  UNIVERSAL-001  Evidence Destruction    → L2 + Manager
  UNIVERSAL-002  Permanent Data Destroy  → L3 + Director
  UNIVERSAL-003  Infra Deletion          → L2 + Manager
  UNIVERSAL-004  Wide-Impact Network     → L3 + IC
  UNIVERSAL-005  Security Controls Off   → L2 + Security Mgr
  UNIVERSAL-006  Privilege Escalation    → L2 + IAM
  UNIVERSAL-007  Production Changes      → L2 + Change Mgr
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Load rules from JSON at module import time ────────────────────────────────
_RULES_PATH = Path(__file__).parent.parent.parent.parent / "data" / "universal_safety_rules.json"

def _load_universal_rules() -> List[Dict[str, Any]]:
    try:
        with open(_RULES_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[UniversalSafetyChecker] Failed to load universal_safety_rules.json: {e}")
        return []

_UNIVERSAL_RULES: List[Dict[str, Any]] = _load_universal_rules()

# Build fast lookup: action_type → rule (first match wins)
_ACTION_TO_RULE: Dict[str, Dict[str, Any]] = {}
for _rule in _UNIVERSAL_RULES:
    for _action in _rule.get("blocked_actions", []):
        if _action not in _ACTION_TO_RULE:
            _ACTION_TO_RULE[_action] = _rule


class UniversalSafetyChecker:
    """
    Layer 0 — Universal Safety Rules enforcer.

    Called by AuditorAgent BEFORE any compliance or CIA check.
    Returns a list of violations for any plan actions that match
    a universal safety rule.
    """

    def check(
        self,
        actions: List[Dict[str, Any]],
        asset: Dict[str, Any],
        alert: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Evaluate all plan actions against universal safety rules.

        Args:
            actions:  list of plan action dicts — must have 'type' or 'action_type' key
            asset:    asset metadata dict (from alert.asset_meta)
            alert:    full OCSF alert dict

        Returns:
            List of violation dicts (empty = no universal violations)
        """
        violations: List[Dict[str, Any]] = []
        environment = self._derive_environment(asset, alert)

        for action in actions:
            action_type = action.get("type") or action.get("action_type", "")
            if not action_type:
                continue

            rule = _ACTION_TO_RULE.get(action_type)
            if not rule:
                continue

            # Check conditional exceptions (e.g., dev-only exemptions for UNIVERSAL-003)
            if self._has_exception(rule, environment, asset):
                # Still generate a warning-level violation so dev actions are visible
                violations.append(self._build_violation(
                    rule=rule,
                    action_type=action_type,
                    enforcement="warn",
                    message=f"[Dev Environment Exception] {rule['violation_message']} "
                            f"Still requires L1 approval in non-prod.",
                    override_note="Conditional exception applies — environment=dev"
                ))
                continue

            violations.append(self._build_violation(
                rule=rule,
                action_type=action_type,
                enforcement=rule["enforcement"],
                message=rule["violation_message"],
            ))

        return violations

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_violation(
        self,
        rule: Dict[str, Any],
        action_type: str,
        enforcement: str,
        message: str,
        override_note: Optional[str] = None,
    ) -> Dict[str, Any]:
        v: Dict[str, Any] = {
            "rule_id": rule["rule_id"],
            "rule_name": rule["rule_name"],
            "rule_type": "universal",
            "violation_type": "universal",
            "severity": rule["severity"],
            "enforcement": enforcement,
            "action": action_type,
            "control_id": rule["rule_id"],
            "framework": "universal",
            "message": message,
            "approval_level": rule.get("approval_level"),
            "route_to": rule.get("route_to"),
            "universal_human_in_loop": rule.get("universal_human_in_loop", True),
            "override_allowed": rule.get("override_allowed", False),
            "source_reference": rule.get("source_reference", ""),
            "pre_execution_requirements": rule.get("pre_execution_requirements", []),
            "metadata": {
                "rationale": rule.get("rationale", ""),
                "blocked_action": action_type,
            },
        }
        if override_note:
            v["metadata"]["override_note"] = override_note
        return v

    def _derive_environment(
        self, asset: Dict[str, Any], alert: Dict[str, Any]
    ) -> str:
        """
        Derive the environment from asset metadata.
        Checks asset_meta.environment, asset_meta.tags, or alert.asset_meta.
        Falls back to 'production' (safe default).
        """
        # Check asset_meta directly
        asset_meta = (
            asset.get("asset_meta")
            or (alert.get("asset_meta") if alert else None)
            or asset
        )
        env = (
            asset_meta.get("environment")
            or asset_meta.get("env")
            or (asset_meta.get("tags") or {}).get("env")
            or (asset_meta.get("tags") or {}).get("environment")
            or "production"  # safe default
        )
        return str(env).lower()

    def _has_exception(
        self, rule: Dict[str, Any], environment: str, asset: Dict[str, Any]
    ) -> bool:
        """
        Check if the asset+environment qualifies for a conditional exception.
        Only UNIVERSAL-003 has a dev-only exception currently.
        """
        exceptions = rule.get("conditional_exceptions")
        if not exceptions:
            return False

        allowed_if = exceptions.get("allowed_if", {})

        # Check environment condition
        if "environment" in allowed_if:
            if environment != allowed_if["environment"]:
                return False
        else:
            return False  # No environment match = no exception

        # Check backup verification (from asset metadata)
        asset_meta = asset.get("asset_meta") or asset
        if allowed_if.get("has_recent_backup"):
            if not asset_meta.get("has_recent_backup", False):
                return False

        if allowed_if.get("verified_backup_valid"):
            if not asset_meta.get("verified_backup_valid", False):
                return False

        if allowed_if.get("no_production_dependencies"):
            if asset_meta.get("has_production_dependencies", True):
                return False

        return True


# Module-level singleton
universal_safety_checker = UniversalSafetyChecker()


def check_universal_safety(
    actions: List[Dict[str, Any]],
    asset: Dict[str, Any],
    alert: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Convenience function — check universal safety rules.
    Returns list of violation dicts.
    """
    return universal_safety_checker.check(actions, asset, alert)
