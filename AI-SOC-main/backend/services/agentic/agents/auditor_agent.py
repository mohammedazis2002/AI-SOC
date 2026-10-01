"""
Auditor Agent - Combined Verification + Compliance
Verifies safety, checks compliance, and generates solutions for violations
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from ..agents.base_agent import BaseAgent
from ..workflows.state import AgentState
from ..config.llm_service import llm_service
from ..config.config import config
from ..agents.audit_knowledge_base import CIA_IMPACT_MAPPING, COMPLIANCE_KB, SAFE_ACTIONS
from ...knowledge_base.kb_context import KBContext, ComplianceControl


class AuditorAgent(BaseAgent):
    """
    Auditor Agent - Comprehensive audit of remediation plans.
    
    Responsibilities:
    1. Layer 1: CIA Triad verification (Confidentiality, Integrity, Availability)
    2. Layer 2: Compliance checking (GDPR, HIPAA, DPDP, etc.)
    3. Layer 3: Impact assessment (users, business, financial)
    4. Layer 4: Safety checks (whitelists, dependencies, rollback)
    5. Generate intelligent solutions for violations
    
    Output: VERIFIED | BLOCKED | ESCALATE
    """
    
    def __init__(self):
        super().__init__("Auditor Agent")
        self.compliance_frameworks = config.COMPLIANCE_FRAMEWORKS
    
    async def execute(self, state: AgentState) -> AgentState:
        """
        Audit remediation playbook.
        """
        self.log_info("=== Auditor Agent: Verification + Compliance ===")
        
        playbook = state["playbook"]
        alert = state["alert"]
        enrichment = alert.get("enrichment", {})

        # Retrieve kb_context from state (populated by reasoning agent Phase 1)
        kb_context: Optional[KBContext] = state.get("kb_context")
        
        # Layer 1: CIA Triad
        self.log_info("Layer 1: CIA Triad verification")
        cia_result = self._verify_cia_triad(playbook, alert)
        
        # Layer 2: Compliance — use real KB controls if available, else hardcoded fallback
        self.log_info("Layer 2: Compliance checking (KB-powered)")
        if kb_context and kb_context.compliance_controls:
            self.log_info(
                f"  Using {len(kb_context.compliance_controls)} controls from Qdrant compliance_kb"
            )
            compliance_result = self._check_compliance_from_kb(
                playbook, alert, kb_context, cia_result
            )
        else:
            self.log_info("  KB context not available — falling back to hardcoded COMPLIANCE_KB")
            compliance_result = await self._check_compliance(playbook, alert, enrichment)
        
        # Layer 3: Impact Assessment
        self.log_info("Layer 3: Impact assessment")
        impact_result = self._assess_impact(playbook, alert)
        
        # Layer 4: Safety Checks
        self.log_info("Layer 4: Safety checks")
        safety_result = self._check_safety(playbook, alert)
        
        # Aggregate results
        audit_result = {
            "cia_triad": cia_result,
            "compliance": compliance_result,
            "impact": impact_result,
            "safety": safety_result,
            "timestamp": datetime.utcnow().isoformat(),
            "compliance_source": "qdrant_kb" if (kb_context and kb_context.compliance_controls) else "local_kb",
        }
        
        # Determine final decision
        final_decision = self._make_audit_decision(audit_result)
        audit_result["decision"] = final_decision
        
        state["audit_result"] = audit_result
        state["timestamp_audit"] = datetime.utcnow()
        
        self.log_info(f"Audit complete: {final_decision} (source: {audit_result['compliance_source']})")
        
        return state
    
    def _verify_cia_triad(self, playbook: Dict[str, Any], alert: Dict[str, Any]) -> Dict[str, Any]:
        """Verify CIA Triad principles using OCSF Class Mapping and Context Rules"""
        
        # 1. Identify the Risk Context
        class_id = str(alert.get("class_uid", "unknown"))
        description = alert.get("message", "").lower()
        
        # Step A: Check Context Rules (Overrides)
        primary_risk = None
        risk_detail = None
        
        from ..agents.audit_knowledge_base import CIA_CONTEXT_RULES
        
        for rule in CIA_CONTEXT_RULES:
            if rule["class_id"] == class_id:
                # Check keywords in description
                for kw in rule["keywords"]:
                    if kw in description:
                        primary_risk = rule["cia"]
                        risk_detail = rule["risk"] + " (Context Override)"
                        break
            if primary_risk:
                break
        
        # Step B: Fallback to Static Mapping
        if not primary_risk:
            impact_info = CIA_IMPACT_MAPPING.get(class_id, CIA_IMPACT_MAPPING.get("Exfiltration"))
            
            # Final Safety Net
            if not impact_info:
                 if "exfiltrat" in description:
                     impact_info = CIA_IMPACT_MAPPING["Exfiltration"]
                 elif "ransomware" in description or "encrypt" in description:
                     impact_info = CIA_IMPACT_MAPPING["Ransomware"]
                 else:
                     impact_info = {"cia": "integrity", "risk": "Unknown Modification"}
            
            primary_risk = impact_info["cia"]
            risk_detail = impact_info["risk"]

        actions = playbook.get("actions", [])
        
        # 2. Evaluate Actions based on Primary Risk
        
        # Confidentiality Check
        confidentiality_issues = []
        if primary_risk == "confidentiality":
            for action in actions:
                if action.get("action_type") in ["upload_data", "publish", "decrypt", "permit_traffic"]:
                    confidentiality_issues.append(f"{action.get('action_type')} (Step {action.get('step')})")
            
        confidentiality_safe = len(confidentiality_issues) == 0

        # Integrity Check
        integrity_issues = []
        if primary_risk == "integrity":
            # Ensure remediation exists
            has_remediation = any(
                action.get("action_type") in SAFE_ACTIONS["remediation"] or 
                action.get("action_type") in SAFE_ACTIONS["recovery"]
                for action in actions
            )
            if not has_remediation:
                integrity_issues.append("Missing remediation or recovery action")
        
        integrity_safe = len(integrity_issues) == 0

        # Availability Check
        availability_issues = []
        for action in actions:
            if action.get("action_type") in ["shutdown", "disable_service", "isolate_host", "block_ip"]:
                availability_issues.append(f"{action.get('action_type')} (Step {action.get('step')})")
        
        availability_risk = len(availability_issues) > 0
        
        return {
            "primary_risk": primary_risk.upper(),
            "risk_detail": risk_detail,
            "confidentiality": {
                "status": "pass" if confidentiality_safe else "fail",
                "details": f"Violations: {', '.join(confidentiality_issues)}" if not confidentiality_safe else "No data leak risks"
            },
            "integrity": {
                "status": "pass" if integrity_safe else "warning",
                "details": f"Issues: {', '.join(integrity_issues)}" if not integrity_safe else "Remediation present"
            },
            "availability": {
                "status": "warning" if availability_risk else "pass",
                "details": f"Impacts: {', '.join(availability_issues)}" if availability_risk else "No availability impact"
            },
            "overall": "pass" if confidentiality_safe and integrity_safe else "warning"
        }
    
    def _check_compliance_from_kb(
        self,
        playbook: Dict[str, Any],
        alert: Dict[str, Any],
        kb_context: KBContext,
        cia_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Layer 2 compliance check using real Qdrant controls from KBContext.

        Each ComplianceControl from the exhaustive sweep is evaluated against the
        playbook: if the playbook has no action that addresses the control's
        primary_risk domain, it is flagged as a potential gap.

        Design:
          - Stage 1 controls (exact technique_id match) are always included as violations.
          - Stage 2 controls (semantic) are flagged only when CIA flags overlap with the
            alert's primary CIA risk (reduces noise).
        """
        primary_cia = cia_result.get("primary_risk", "").lower()   # e.g. "confidentiality"
        playbook_action_types = {a.get("action_type", "") for a in playbook.get("actions", [])}
        playbook_text = json.dumps(playbook.get("actions", []))

        # Safe remediation action types that satisfy integrity/availability controls
        remediation_types = {
            "isolate", "block_ip", "disable_account", "reset_password", "patch",
            "quarantine", "rollback", "restore", "collect_evidence", "investigate",
            "revoke_access", "notify", "escalate", "audit_log",
        }

        violations: List[Dict[str, Any]] = []
        frameworks_seen: set = set()

        for ctrl in kb_context.compliance_controls:
            frameworks_seen.add(ctrl.framework)
            cia_flags = ctrl.cia_flags or {}

            # For semantic-only matches: only flag if CIA risk overlaps with incident CIA
            if ctrl.match_type == "semantic":
                ctrl_cia_domains = {k for k, v in cia_flags.items() if v}
                if primary_cia and primary_cia not in ctrl_cia_domains:
                    continue   # Skip low-signal semantic controls

            # Heuristic: playbook missing relevant remediation actions = gap
            has_relevant_action = bool(playbook_action_types & remediation_types)
            if ctrl.match_type == "exact" and not has_relevant_action:
                # Direct technique match + no remediation = definite gap
                violation = {
                    "framework": ctrl.framework,
                    "control_id": ctrl.control_id,
                    "control_name": ctrl.control_name,
                    "requirement": ctrl.description[:200],
                    "parent_chain": " > ".join(ctrl.parent_chain),
                    "cia_flags": cia_flags,
                    "match_type": "exact",
                    "issue": f"Control directly mapped to technique — playbook missing remediation action",
                    "severity_weight": ctrl.severity_weight,
                }
                violations.append(violation)
            elif ctrl.match_type == "semantic" and primary_cia:
                # Only flag semantic controls as informational (lower severity)
                cia_covered = cia_flags.get(primary_cia, False)
                if cia_covered:
                    violation = {
                        "framework": ctrl.framework,
                        "control_id": ctrl.control_id,
                        "control_name": ctrl.control_name,
                        "requirement": ctrl.description[:200],
                        "parent_chain": " > ".join(ctrl.parent_chain),
                        "cia_flags": cia_flags,
                        "match_type": "semantic",
                        "issue": f"Control semantically relevant to alert — review {primary_cia} controls",
                        "severity_weight": ctrl.severity_weight * 0.6,  # lower weight for semantic
                    }
                    violations.append(violation)

        # Group by framework for structured reporting
        by_framework: Dict[str, List[Dict]] = {}
        for v in violations:
            by_framework.setdefault(v["framework"], []).append(v)

        return {
            "frameworks_checked": sorted(frameworks_seen),
            "frameworks_with_violations": sorted(by_framework.keys()),
            "violations_found": len(violations),
            "violations": violations,
            "violations_by_framework": {
                fw: [{"control_id": v["control_id"],
                      "control_name": v["control_name"],
                      "issue": v["issue"],
                      "match_type": v["match_type"],
                      "parent_chain": v["parent_chain"]}
                     for v in vlist]
                for fw, vlist in by_framework.items()
            },
            "status": "compliant" if len(violations) == 0 else "violations_found",
            "note": "Source: Qdrant compliance_kb — exhaustive 4-stage audit sweep",
        }

    async def _check_compliance(
        self,
        playbook: Dict[str, Any],
        alert: Dict[str, Any],
        enrichment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        FALLBACK: Check compliance using hardcoded Knowledge Base.
        Used when Qdrant KB context is not yet available.
        """
        
        violations = []
        solutions = []
        
        playbook_actions = [a.get("action_type", "") for a in playbook.get("actions", [])]
        playbook_text = json.dumps(playbook.get("actions", []))
        
        # Check each framework in KB
        for framework, kb_data in COMPLIANCE_KB.items():
            if framework not in self.compliance_frameworks:
                continue
                
            # 1. Check Applicability (Context)
            is_applicable = False
            
            # Check enrichment flags (e.g., has_pii, has_pci)
            for context_flag in kb_data["context"]:
                # Check directly in enrichment OR in alert top-level (legacy)
                if enrichment.get(context_flag) or alert.get(context_flag):
                    is_applicable = True
                    break
            
            if not is_applicable:
                continue
                
            # 2. Check Controls
            for control_key, control in kb_data["controls"].items():
                required = control["required_action"]
                
                compliance_met = False
                if required in playbook_actions:
                    compliance_met = True
                elif required in playbook_text:
                    compliance_met = True
                
                if not compliance_met:
                    violation = {
                        "framework": framework,
                        "control_id": control["id"],
                        "requirement": control["requirement"],
                        "issue": f"Missing required action: {control['name']} ({required})",
                        "control_def": control
                    }
                    violations.append(violation)
                    
                    # Generate Solution
                    solution = await self._generate_compliance_solution(
                        framework,
                        violation,
                        playbook
                    )
                    solutions.append(solution)
        
        return {
            "frameworks_checked": self.compliance_frameworks,
            "violations_found": len(violations),
            "violations": violations,
            "solutions": solutions,
            "status": "compliant" if len(violations) == 0 else "violations_found",
            "note": "Source: local hardcoded KB (fallback)",
        }
    
    async def _generate_compliance_solution(
        self,
        framework: str,
        violation: Dict[str, Any],
        playbook: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate intelligent solution for compliance violation using LLM and KB"""
        
        self.log_info(f"Generating solution for {framework} violation")
        
        try:
            control = violation.get("control_def", {})
            
            prompt = f"""A compliance violation was detected. Generate a specific remediation action.

**CONTEXT:**
Framework: {framework}
Control: {control.get('id')} - {control.get('name')}
Requirement: {control.get('requirement')}
Missing Action: {control.get('required_action')}
Description: {control.get('description')}

**CURRENT PLAYBOOK:**
{json.dumps(playbook.get('actions', [])[:3], indent=2)}

**TASK:**
Generate a JSON object for the MISSING action. It must satisfy the requirement above.

**OUTPUT FORMAT:**
{{
    "action": {{
        "step": <insert_after_step>,
        "action_type": "{control.get('required_action')}",
        "target": "target_system_or_user",
        "command": "<specific command to run>",
        "expected_result": "Compliance requirement met",
        "rollback": "<rollback_strategy>"
    }},
    "explanation": "Why this fulfills {framework} {control.get('id')}",
    "compliance_met": true
}}

Respond ONLY with valid JSON."""
            
            llm_response = await llm_service.ainvoke(
                prompt=prompt,
                tier="secondary",
                system_message="You are a GRC expert. Provide precise technical actions for compliance."
            )
            
            # Parse response
            solution = json.loads(llm_response.content)
            solution["framework"] = framework
            solution["generated_by"] = "llm_kb_enriched"
            
            return solution
            
        except Exception as e:
            self.log_error(f"Error generating solution: {e}", exc_info=True)
            # Fallback to KB definition
            return {
                "action": {
                    "step": 1, 
                    "action_type": control.get("required_action", "review"),
                    "target": "compliance_officer",
                    "command": "Manual Review Required"
                },
                "explanation": f"Fallback: {control.get('requirement')}",
                "compliance_met": False,
                "framework": framework,
                "generated_by": "fallback_kb"
            }
    
    def _assess_impact(self, playbook: Dict[str, Any], alert: Dict[str, Any]) -> Dict[str, Any]:
        """Assess impact of remediation actions"""
        actions = playbook.get("actions", [])
        
        # User impact
        user_affected = sum(
            1 for action in actions
            if action.get("action_type") in ["disable_account", "revoke_access", "reset_password"]
        )
        
        # Business impact
        business_critical = any(
            action.get("action_type") in ["shutdown", "disable_service", "isolate_host"]
            for action in actions
        )
        
        return {
            "users_affected": user_affected,
            "business_critical": business_critical,
            "overall_impact": "high" if business_critical else "medium" if user_affected > 5 else "low"
        }
    
    def _check_safety(self, playbook: Dict[str, Any], alert: Dict[str, Any]) -> Dict[str, Any]:
        """Safety checks using safe action lists"""
        actions = playbook.get("actions", [])
        
        # Flatten safe actions list
        all_safe = [a for cats in SAFE_ACTIONS.values() for a in cats]
        
        # Actions that are NOT in our safe list
        unknown_actions = [
            action for action in actions
            if action.get("action_type") not in all_safe
        ]
        
        # Check rollback plans exist
        missing_rollback = [
            action for action in actions
            if (not action.get("rollback") or action.get("rollback") == "N/A")
            and action.get("action_type") not in SAFE_ACTIONS["analysis"]
        ]
        
        return {
            "unknown_actions": len(unknown_actions),
            "missing_rollback": len(missing_rollback),
            "status": "safe" if len(unknown_actions) == 0 and len(missing_rollback) <= 1 else "unsafe"
        }
    
    def _make_audit_decision(self, audit_result: Dict[str, Any]) -> str:
        """Make final audit decision"""
        
        # BLOCKING CONDITIONS
        # 1. Unsafe actions detected
        if audit_result["safety"]["status"] == "unsafe":
            return "BLOCKED"
        
        # 2. Confidentiality Failure (Data Leak)
        if audit_result["cia_triad"]["confidentiality"]["status"] == "fail":
            return "BLOCKED"
        
        # ESCALATION CONDITIONS
        # 1. Business Critical Impact (Shutdowns)
        if audit_result["impact"]["business_critical"]:
            return "ESCALATE"
        
        # 2. Multiple Compliance Violations
        if audit_result["compliance"]["violations_found"] > 2:
            return "ESCALATE"
        
        # 3. Warning on CIA (e.g., Integrity/Availability risk without clear mitigation)
        if audit_result["cia_triad"]["overall"] == "warning":
             return "ESCALATE"
        
        # Otherwise verify
        return "VERIFIED"
    
    def validate_input(self, state: AgentState) -> bool:
        """Validate playbook exists"""
        return "playbook" in state
