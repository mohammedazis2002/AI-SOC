"""
Compliance Rules Checker — Layer 2 (Primary) of the Auditor Agent
==================================================================
Evaluates remediation plan actions against compliance_rules_full.json.
This is Path C — the authoritative, deterministic compliance enforcement
layer based on the 290 canonical control rules.

Architecture:
  Path A (Qdrant)  → Secondary gap-finding (semantic match)
  Path B (COMPLIANCE_KB)→ Tertiary offline fallback
  Path C (THIS)    → PRIMARY ENFORCEMENT (exact match, all 11 frameworks)

Rule Types:
  action_blocklist    → Plan contains a forbidden action (enforcement=reject/require_approval)
  required_action     → Plan is MISSING a required action (enforcement=require_modification/warn)
  required_approval   → Action is allowed but needs explicit approval flag
  action_sequence     → Action ordering violated
  conditional_block   → Action blocked only when applies_when context matches

Dynamic Context (for applies_when evaluation):
  Derived at runtime from alert + asset — NOT hardcoded.
  See _derive_context() for derivation logic.
"""

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Load rules at module import ───────────────────────────────────────────────
_RULES_PATH = (
    Path(__file__).parent.parent.parent.parent / "data" / "compliance_rules_full.json"
)


def _load_rules() -> List[Dict[str, Any]]:
    try:
        with open(_RULES_PATH, encoding="utf-8") as f:
            rules = json.load(f)
        logger.info(f"[ComplianceRulesChecker] Loaded {len(rules)} rules from compliance_rules_full.json")
        return rules
    except Exception as e:
        logger.error(f"[ComplianceRulesChecker] Failed to load compliance_rules_full.json: {e}")
        return []


_ALL_RULES: List[Dict[str, Any]] = _load_rules()

# Framework name normalisers — map various forms to our canonical keys
_FW_ALIASES: Dict[str, str] = {
    "pci_dss": "pci_dss",
    "pci-dss": "pci_dss",
    "pci": "pci_dss",
    "gdpr": "gdpr",
    "hipaa": "hipaa",
    "iso27001": "iso_27001_2022",
    "iso_27001": "iso_27001_2022",
    "iso_27001_2022": "iso_27001_2022",
    "nist800-53": "nist_800_53",
    "nist_800_53": "nist_800_53",
    "nist-800-53": "nist_800_53",
    "soc2": "soc_2",
    "soc_2": "soc_2",
    "cis": "cis_controls_v8",
    "cis_controls_v8": "cis_controls_v8",
    "sebi": "sebi_cscrf",
    "sebi_cscrf": "sebi_cscrf",
    "dpdp": "dpdp_act_2023",
    "dpdp_act_2023": "dpdp_act_2023",
    "iso42001": "iso_42001",
    "iso_42001": "iso_42001",
    "nist_csf_2_0": "nist_csf_2_0",
    "nist-csf": "nist_csf_2_0",
    "nist_csf": "nist_csf_2_0",
}

# Build per-framework rule indexes
_FW_RULES: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
for _r in _ALL_RULES:
    _FW_RULES[_r["framework"]].append(_r)


class ComplianceRulesChecker:
    """
    Primary (Path C) compliance enforcement layer.

    Checks the remediation plan against compliance_rules_full.json using the
    asset's compliance_scope to select applicable frameworks, then evaluates
    each action against the appropriate rules.
    """

    def check(
        self,
        actions: List[Dict[str, Any]],
        asset: Dict[str, Any],
        alert: Dict[str, Any],
        frameworks: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate plan actions against compliance rules.

        Two-pass design:
          Pass 1 (GLOBAL — all 290 rules):
            action_blocklist + conditional_block rules are checked against ALL rules
            regardless of framework tags. If an action is forbidden in PCI-DSS but the
            asset is only tagged GDPR, we still catch it. The action type is the filter, not
            the framework scope.

          Pass 2 (SCOPED — framework-filtered):
            required_action, required_approval, action_sequence rules are jurisdiction-
            specific. These only apply to frameworks the asset is actually in scope for.
            (You can't be obligated to do something by a standard you don't fall under.)

        Args:
            actions:    list of plan action dicts
            asset:      asset metadata
            alert:      full OCSF alert dict
            frameworks: override framework list for Pass 2 (if None, derived from asset tags)
        """
        ctx = self._derive_context(asset, alert)
        plan_action_types: Set[str] = {
            a.get("type") or a.get("action_type", "") for a in actions
        }
        plan_action_types.discard("")

        all_violations: List[Dict[str, Any]] = []
        checked_fws: Set[str] = set()

        # ── Pass 1: Global blocklist (all frameworks, all 290 rules) ─────────
        # Primary filter is action type. Framework tags don't limit this pass.
        for rule in _ALL_RULES:
            if rule.get("rule_type") not in {"action_blocklist", "conditional_block"}:
                continue
            if not self._rule_applies(rule, ctx):
                continue
            violation = self._evaluate_rule(rule, plan_action_types, actions)
            if violation:
                violation = self._apply_tactic_filter(violation, rule, ctx)
                checked_fws.add(rule["framework"])
                all_violations.append(violation)

        # ── Pass 2: Scoped required/approval/sequence (framework-filtered) ───
        applicable_fws = self._resolve_frameworks(frameworks, asset, alert)
        for fw in applicable_fws:
            canonical_fw = _FW_ALIASES.get(fw.lower(), fw.lower())
            fw_rules = _FW_RULES.get(canonical_fw, [])
            if not fw_rules:
                logger.warning(f"[ComplianceRulesChecker] No rules found for framework: {canonical_fw}")
                continue

            checked_fws.add(canonical_fw)

            for rule in fw_rules:
                if rule.get("rule_type") in {"action_blocklist", "conditional_block"}:
                    continue   # already handled in Pass 1
                if not self._rule_applies(rule, ctx):
                    continue
                violation = self._evaluate_rule(rule, plan_action_types, actions)
                if violation:
                    violation = self._apply_tactic_filter(violation, rule, ctx)
                    all_violations.append(violation)

        return self._build_result(all_violations, checked_fws)


    # ── Rule application ──────────────────────────────────────────────────────
    
    def _apply_tactic_filter(self, violation: Dict[str, Any], rule: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Downgrade enforcement of certain controls if they are strategically irrelevant to the tactic."""
        incident_type = ctx.get("incident_type", "")
        tactic = ctx.get("tactic", "")
        has_pii = ctx.get("has_pii", False)
        
        # If it's pure reconnaissance and NO personal data is definitively involved
        if incident_type == "reconnaissance" or tactic == "discovery":
            if not has_pii:
                cid = rule.get("control_id", "").lower()
                issue = violation.get("issue", "").lower()
                
                # GDPR Data Subject Rights (17: erasure, 18: restriction, 20: portability, 21: objection)
                # HIPAA Emergency Mode / Backup Plans
                is_irrelevant = (
                    "art. 17" in cid or "art. 18" in cid or "art. 20" in cid or "art. 21" in cid
                    or "emergency" in issue or "backup" in issue or "consent" in issue
                )
                
                if is_irrelevant and violation["enforcement"] in ("require_modification", "reject"):
                    violation["enforcement"] = "warn"
                    violation["fix_suggestion"] += " (NOTE: Downgraded to 'warn' because incident is Reconnaissance and no PII is involved)"
        
        return violation

    def _evaluate_rule(
        self,
        rule: Dict[str, Any],
        plan_action_types: Set[str],
        actions: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a single rule against the plan. Returns violation or None."""
        rule_type = rule.get("rule_type", "")

        if rule_type == "action_blocklist":
            return self._check_blocklist(rule, plan_action_types)

        elif rule_type == "required_action":
            return self._check_required_action(rule, plan_action_types)

        elif rule_type == "required_approval":
            return self._check_required_approval(rule, actions)

        elif rule_type == "conditional_block":
            return self._check_conditional_block(rule, plan_action_types)

        elif rule_type == "action_sequence":
            return self._check_action_sequence(rule, actions)

        return None

    def _check_blocklist(
        self, rule: Dict[str, Any], plan_types: Set[str]
    ) -> Optional[Dict[str, Any]]:
        """action_blocklist: plan contains a forbidden action."""
        blocked = set(rule.get("blocked_actions", []))
        hits = plan_types & blocked
        if not hits:
            return None
        hit = next(iter(hits))
        return self._build_violation(
            rule=rule,
            action=hit,
            issue=f"Action '{hit}' is explicitly blocked by {rule['framework'].upper()} "
                  f"control {rule['control_id']}",
            fix_suggestion=rule.get("recommendation", "Remove or replace this action"),
        )

    def _check_required_action(
        self, rule: Dict[str, Any], plan_types: Set[str]
    ) -> Optional[Dict[str, Any]]:
        """required_action: plan is MISSING a required action."""
        required = rule.get("required_action", "")
        if not required or required in plan_types:
            return None
        return self._build_violation(
            rule=rule,
            action=required,
            issue=f"Missing required action '{required}' per {rule['framework'].upper()} "
                  f"control {rule['control_id']}",
            fix_suggestion=rule.get("recommendation",
                f"Add '{required}' to the remediation plan"),
        )

    def _check_required_approval(
        self, rule: Dict[str, Any], actions: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """required_approval: action exists but lacks approval flag."""
        approval_actions = set(rule.get("actions_requiring_approval", []))
        for action in actions:
            atype = action.get("type") or action.get("action_type", "")
            if atype in approval_actions:
                # Check if action already annotated with requires_approval=True
                if not action.get("requires_approval", False):
                    return self._build_violation(
                        rule=rule,
                        action=atype,
                        issue=f"Action '{atype}' requires explicit approval per "
                              f"{rule['framework'].upper()} {rule['control_id']}. "
                              f"Mark 'requires_approval: true' in the plan.",
                        fix_suggestion=rule.get("recommendation",
                            f"Set requires_approval=true on action '{atype}'"),
                    )
        return None

    def _check_conditional_block(
        self, rule: Dict[str, Any], plan_types: Set[str]
    ) -> Optional[Dict[str, Any]]:
        """conditional_block: action blocked in specific context (context already confirmed via _rule_applies)."""
        blocked = set(rule.get("blocked_actions", []))
        hits = plan_types & blocked
        if not hits:
            return None
        hit = next(iter(hits))
        return self._build_violation(
            rule=rule,
            action=hit,
            issue=f"Action '{hit}' is conditionally blocked by {rule['framework'].upper()} "
                  f"control {rule['control_id']} in current incident context",
            fix_suggestion=rule.get("recommendation",
                "Consider an alternative action that meets the remediation goal without this action"),
        )

    def _check_action_sequence(
        self, rule: Dict[str, Any], actions: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """action_sequence: action ordering must match the rule's sequence constraint."""
        must_before = rule.get("must_execute_before")  # action A must precede action B
        if not must_before or not isinstance(must_before, list) or len(must_before) < 2:
            return None

        before_action, after_action = must_before[0], must_before[1]

        # Find positions in plan
        types = [a.get("type") or a.get("action_type", "") for a in actions]
        before_idx = next((i for i, t in enumerate(types) if t == before_action), None)
        after_idx = next((i for i, t in enumerate(types) if t == after_action), None)

        if before_idx is None or after_idx is None:
            return None  # One or both not present — handled by required_action check

        if before_idx > after_idx:
            return self._build_violation(
                rule=rule,
                action=after_action,
                issue=f"Sequence violation: '{before_action}' must execute BEFORE "
                      f"'{after_action}' per {rule['framework'].upper()} {rule['control_id']}",
                fix_suggestion=f"Reorder the plan so '{before_action}' appears before '{after_action}'",
            )
        return None

    # ── Context derivation ────────────────────────────────────────────────────

    def _derive_context(
        self, asset: Dict[str, Any], alert: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Derive runtime execution context from asset + alert.
        This is the DYNAMIC context used for applies_when evaluation.
        Nothing is hardcoded — all values come from live data.
        """
        asset_meta = asset.get("asset_meta") or asset or {}
        enrichments = alert.get("enrichments") or {}
        mitre = enrichments.get("mitre") or {}

        # Incident type: derived from OCSF class_uid + MITRE tactic
        class_uid = str(alert.get("class_uid", ""))
        tactic = mitre.get("tactic_name", "").lower()
        incident_type = self._classify_incident_type(class_uid, tactic, alert)

        # Geography: from asset geo field or IP geolocation enrichment
        geo = (
            asset_meta.get("geo")
            or asset_meta.get("location")
            or enrichments.get("geo", {}).get("country_code", "")
        )

        # Environment: from asset tags
        env = (
            asset_meta.get("environment")
            or asset_meta.get("env")
            or (asset_meta.get("tags") or {}).get("env", "production")
        ).lower()

        # Data sensitivity flags
        has_pii = (
            asset_meta.get("has_pii")
            or alert.get("has_pii")
            or "pii" in str(asset_meta.get("data_classification", "")).lower()
        )
        has_phi = (
            asset_meta.get("has_phi")
            or alert.get("has_phi")
            or "phi" in str(asset_meta.get("data_classification", "")).lower()
        )
        has_cardholder_data = (
            asset_meta.get("has_pci")
            or alert.get("has_pci")
            or "cardholder" in str(asset_meta.get("data_classification", "")).lower()
        )

        return {
            "incident_type": incident_type,
            "geography": str(geo).upper() if geo else "",
            "environment": env,
            "has_pii": bool(has_pii),
            "has_phi": bool(has_phi),
            "has_cardholder_data": bool(has_cardholder_data),
            "asset_criticality": asset_meta.get("criticality", "medium").lower(),
            "tactic": tactic,
            "class_uid": class_uid,
            "compliance_scope": asset_meta.get("compliance_zones") or asset_meta.get("compliance_scope") or [],
        }

    def _classify_incident_type(
        self, class_uid: str, tactic: str, alert: Dict[str, Any]
    ) -> str:
        """
        Derive incident_type from OCSF class_uid + MITRE tactic.
        This mirrors what the Investigation Agent derives, but computed locally
        to avoid circular dependency.
        """
        desc = str(alert.get("message", "") + alert.get("type_name", "")).lower()

        # Map MITRE tactics / OCSF classes to incident types
        if tactic in {"exfiltration", "collection"} or class_uid.startswith("4") and "exfil" in desc:
            return "data_breach"
        if tactic == "impact" or "ransom" in desc or "wiper" in desc:
            return "ransomware"
        if tactic in {"lateral_movement", "persistence"}:
            return "lateral_movement"
        if class_uid.startswith("3") or tactic == "initial_access":
            return "credential_compromised"
        if tactic == "defense_evasion" or "log" in desc and "delet" in desc:
            return "defense_evasion"
        if tactic == "discovery" or class_uid.startswith("5"):
            return "reconnaissance"
        if tactic in {"command_and_control"}:
            return "c2_communication"

        return "security_incident"  # fallback

    def _rule_applies(
        self, rule: Dict[str, Any], ctx: Dict[str, Any]
    ) -> bool:
        """
        Check if a rule's applies_when conditions are met by the current context.
        `applies_when` in the JSON is a FILTER — conditions must match for the rule to fire.
        All defined conditions must be satisfied (AND logic).
        """
        applies_when = rule.get("applies_when")
        if not applies_when:
            return True  # No condition = always applies

        # incident_type gate
        allowed_types = applies_when.get("incident_type")
        if allowed_types:
            if ctx.get("incident_type") not in allowed_types:
                return False

        # asset_compliance_scope gate (overlap required)
        required_scope = applies_when.get("asset_compliance_scope")
        if required_scope:
            asset_scope = [s.lower() for s in (ctx.get("compliance_scope") or [])]
            if not any(s in asset_scope for s in [r.lower() for r in required_scope]):
                return False

        # environment gate
        allowed_env = applies_when.get("environment")
        if allowed_env:
            if isinstance(allowed_env, list):
                if ctx.get("environment") not in allowed_env:
                    return False
            elif ctx.get("environment") != allowed_env:
                return False

        # geography gate
        allowed_geo = applies_when.get("geography")
        if allowed_geo:
            geo = ctx.get("geography", "")
            if not any(geo.startswith(g.upper()) for g in (allowed_geo if isinstance(allowed_geo, list) else [allowed_geo])):
                return False

        # criticality gate
        allowed_crit = applies_when.get("asset_criticality")
        if allowed_crit:
            if ctx.get("asset_criticality") not in (allowed_crit if isinstance(allowed_crit, list) else [allowed_crit]):
                return False

        return True

    # ── Framework resolution ──────────────────────────────────────────────────

    def _resolve_frameworks(
        self,
        override: Optional[List[str]],
        asset: Dict[str, Any],
        alert: Dict[str, Any],
    ) -> List[str]:
        """Resolve which frameworks apply to this asset."""
        if override:
            return [_FW_ALIASES.get(f.lower(), f.lower()) for f in override]

        asset_meta = asset.get("asset_meta") or asset or {}
        zones = (
            asset_meta.get("compliance_zones")
            or asset_meta.get("compliance_scope")
            or alert.get("compliance_scope")
            or []
        )
        return [_FW_ALIASES.get(z.lower(), z.lower()) for z in zones]

    # ── Result building ───────────────────────────────────────────────────────

    def _build_violation(
        self,
        rule: Dict[str, Any],
        action: str,
        issue: str,
        fix_suggestion: str,
    ) -> Dict[str, Any]:
        return {
            "rule_id": rule.get("rule_id", ""),
            "rule_type": rule.get("rule_type", ""),
            "violation_type": "compliance",
            "severity": rule.get("severity", "medium"),
            "enforcement": rule.get("enforcement", "warn"),
            "action": action,
            "control_id": rule.get("control_id", ""),
            "control_name": rule.get("control_name", ""),
            "framework": rule.get("framework", ""),
            "message": rule.get("violation_message", issue),
            "issue": issue,
            "fix_suggestion": fix_suggestion,
            "recommendation": rule.get("recommendation", ""),
            "metadata": {
                "rule_source": "compliance_rules_full.json",
                "path": "C",
            },
        }

    def _build_result(
        self,
        violations: List[Dict[str, Any]],
        checked_fws: Set[str],
        note: str = "",
    ) -> Dict[str, Any]:
        from collections import Counter
        by_framework: Dict[str, list] = {}
        for v in violations:
            by_framework.setdefault(v["framework"], []).append(v)

        enforcement_counts = Counter(v["enforcement"] for v in violations)

        return {
            "source": "compliance_rules_full.json (Path C — primary enforcement)",
            "frameworks_checked": sorted(checked_fws),
            "frameworks_with_violations": sorted(by_framework.keys()),
            "violations_found": len(violations),
            "violations": violations,
            "violations_by_framework": {
                fw: [{"control_id": v["control_id"], "control_name": v["control_name"],
                      "issue": v["issue"], "enforcement": v["enforcement"],
                      "fix_suggestion": v["fix_suggestion"]}
                     for v in vlist]
                for fw, vlist in by_framework.items()
            },
            "enforcement_summary": dict(enforcement_counts),
            "status": "compliant" if not violations else "violations_found",
            "note": note,
        }


# Module-level singleton
compliance_rules_checker = ComplianceRulesChecker()
