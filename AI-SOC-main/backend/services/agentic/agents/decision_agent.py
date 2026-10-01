"""
Decision Engine - Auto-Execute vs Manual Review
Rule-based decision making with comprehensive reporting
"""

import json
from datetime import datetime
from typing import Dict, Any

from ..agents.base_agent import BaseAgent
from ..workflows.state import AgentState
from ..tools.redis_queue import redis_queue
from ..tools.mongodb_helper import mongodb_helper
from ..config.config import config


class DecisionAgent(BaseAgent):
    """
    Decision Engine - Makes auto-execute or manual review decision.
    
    Responsibilities:
    1. Apply decision rules
    2. Check audit result
    3. Check action safety
    4. Generate comprehensive report
    5. Queue for manual review OR approve for auto-execute
    """
    
    def __init__(self):
        super().__init__("Decision Engine")
    
    async def execute(self, state: AgentState) -> AgentState:
        """
        Make auto-execute or manual review decision.
        
        Args:
            state: Complete agent state with all outputs
            
        Returns:
            State with decision and report
        """
        self.log_info("=== Decision Engine: Auto-Execute vs Manual Review ===")
        
        # Extract data
        alert = state["alert"]
        playbook = state["playbook"]
        audit_result = state["audit_result"]
        reasoning = state.get("reasoning_synthesis", {})
        priority = state.get("priority", "P3")
        
        # Step 1: Check audit decision
        audit_decision = audit_result.get("decision", "ESCALATE")
        
        self.log_info(f"Audit decision: {audit_decision}")
        
        # Step 2: Apply decision rules
        decision, reason = self._apply_decision_rules(
            audit_decision,
            playbook,
            audit_result,
            alert,
            priority
        )
        
        self.log_info(f"Final decision: {decision} ({reason})")
        
        # Step 3: Generate comprehensive report
        report = self._generate_report(state, decision, reason)
        
        # Step 4: Take action based on decision
        if decision == "AUTO_EXECUTE":
            self.log_info("Approved for auto-execution")
            # Save to MongoDB
            incident_data = self._build_incident_document(state, decision, report)
            mongodb_helper.save_incident(incident_data)
            
        else:  # MANUAL_REVIEW
            self.log_info(f"Queuing for manual review: {reason}")
            # Add to Redis queue
            redis_queue.push_to_review_queue(
                incident_id=state["incident_id"],
                priority=priority,
                reason=reason,
                metadata={
                    "audit_decision": audit_decision,
                    "compliance_violations": audit_result.get("compliance", {}).get("violations_found", 0),
                    "safety_status": audit_result.get("safety", {}).get("status"),
                    "impact": audit_result.get("impact", {}).get("overall_impact")
                }
            )
            
            # Also save to MongoDB
            incident_data = self._build_incident_document(state, decision, report)
            mongodb_helper.save_incident(incident_data)
        
        # Update state
        state["decision"] = decision
        state["report"] = report
        state["timestamp_decision"] = datetime.utcnow()
        
        # Calculate total processing time
        if "execution_started" in state:
            state["execution_ended"] = datetime.utcnow()
            processing_time = (state["execution_ended"] - state["execution_started"]).total_seconds()
            state["total_processing_time_seconds"] = processing_time
            self.log_info(f"Total pipeline time: {processing_time:.2f}s")
        
        return state
    
    def _apply_decision_rules(
        self,
        audit_decision: str,
        playbook: Dict[str, Any],
        audit_result: Dict[str, Any],
        alert: Dict[str, Any],
        priority: str
    ) -> tuple:
        """
        Apply decision rules.
        
        Returns:
            (decision, reason) tuple
        """
        
        # Rule 1: BLOCKED by audit → Manual review
        if audit_decision == "BLOCKED":
            return ("MANUAL_REVIEW", "Audit blocked auto-execution (safety/compliance violation)")
        
        # Rule 2: ESCALATE by audit → Manual review
        if audit_decision == "ESCALATE":
            return ("MANUAL_REVIEW", "Audit requires manual review (high impact/complexity)")
        
        # Rule 3: P1 incidents → Manual review for critical decisions
        if priority == "P1":
            return ("MANUAL_REVIEW", "P1 critical incident requires human oversight")
        
        # Rule 4: Compliance violations → Manual review
        compliance = audit_result.get("compliance", {})
        if compliance.get("violations_found", 0) > 0:
            return ("MANUAL_REVIEW", f"Compliance violations detected: {compliance.get('violations_found')}")
        
        # Rule 5: High business impact → Manual review
        impact = audit_result.get("impact", {})
        if impact.get("business_critical"):
            return ("MANUAL_REVIEW", "Business-critical systems affected")
        
        # Rule 6: Check action safety
        safety = audit_result.get("safety", {})
        if safety.get("unsafe_actions", 0) > 0:
            return ("MANUAL_REVIEW", "Unsafe actions in playbook")
        
        # Rule 7: Check if requires approval
        if playbook.get("requires_approval"):
            return ("MANUAL_REVIEW", "Playbook requires manual approval")
        
        # Rule 8: All checks passed → Auto-execute
        return ("AUTO_EXECUTE", "All safety and compliance checks passed")
    
    def _generate_report(
        self,
        state: AgentState,
        decision: str,
        reason: str
    ) -> Dict[str, Any]:
        """Generate comprehensive incident report"""
        
        alert = state["alert"]
        reasoning = state.get("reasoning_synthesis", {})
        playbook = state["playbook"]
        audit_result = state["audit_result"]
        ml_results = state.get("ml_results", {})
        
        report = {
            "incident_id": state["incident_id"],
            "priority": state.get("priority"),
            "decision": decision,
            "decision_reason": reason,
            "generated_at": datetime.utcnow().isoformat(),
            
            # Alert summary
            "alert_summary": {
                "attack_type": alert.get("attack_type"),
                "severity": alert.get("severity"),
                "asset": alert.get("asset_id"),
                "user": alert.get("user"),
                "timestamp": alert.get("timestamp")
            },
            
            # Analysis summary
            "analysis": {
                "final_assessment": reasoning.get("final_assessment"),
                "attack_stage": reasoning.get("attack_stage"),
                "confidence": reasoning.get("confidence"),
                "key_indicators": reasoning.get("key_indicators", []),
                "attacker_objective": reasoning.get("attacker_objective")
            },
            
            # ML results summary
            "ml_analysis": {
                "services_called": ml_results.get("services_called", []),
                "successes": ml_results.get("successes", 0),
                "failures": ml_results.get("failures", 0),
                "degraded": ml_results.get("degraded", False)
            },
            
            # Remediation plan
            "remediation": {
                "objective": playbook.get("objective"),
                "actions_count": len(playbook.get("actions", [])),
                "estimated_time_minutes": playbook.get("estimated_time_minutes"),
                "priority": playbook.get("priority"),
                "actions": playbook.get("actions", [])
            },
            
            # Audit results
            "audit": {
                "decision": audit_result.get("decision"),
                "cia_triad": audit_result.get("cia_triad", {}).get("overall"),
                "compliance_violations": audit_result.get("compliance", {}).get("violations_found", 0),
                "compliance_solutions": len(audit_result.get("compliance", {}).get("solutions", [])),
                "impact_level": audit_result.get("impact", {}).get("overall_impact"),
                "safety_status": audit_result.get("safety", {}).get("status")
            },
            
            # Execution metadata
            "execution": {
                "total_time_seconds": state.get("total_processing_time_seconds"),
                "supervisor_time": self._get_agent_time(state, "supervisor"),
                "reasoning_p1_time": self._get_agent_time(state, "reasoning_p1"),
                "planning_time": self._get_agent_time(state, "planning"),
                "reasoning_p2_time": self._get_agent_time(state, "reasoning_p2"),
                "remediation_time": self._get_agent_time(state, "remediation"),
                "audit_time": self._get_agent_time(state, "audit"),
                "decision_time": self._get_agent_time(state, "decision")
            }
        }
        
        return report
    
    def _get_agent_time(self, state: AgentState, agent: str) -> float:
        """Calculate agent execution time from timestamps"""
        timestamp_key = f"timestamp_{agent}"
        
        if timestamp_key in state:
            # Calculate from execution_started or previous agent
            return 0.0  # Simplified - would calculate actual delta
        
        return 0.0
    
    def _build_incident_document(
        self,
        state: AgentState,
        decision: str,
        report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build complete incident document for MongoDB"""
        
        return {
            "incident_id": state["incident_id"],
            "decision": decision,
            "priority": state.get("priority"),
            "status": "queued_for_review" if decision == "MANUAL_REVIEW" else "approved_for_execution",
            
            # Complete state
            "alert": state["alert"],
            "reasoning_hypothesis": state.get("reasoning_hypothesis"),
            "reasoning_synthesis": state.get("reasoning_synthesis"),
            "ml_results": state.get("ml_results"),
            "playbook": state["playbook"],
            "audit_result": state["audit_result"],
            "report": report,
            
            # Metadata
            "processing_time_seconds": state.get("total_processing_time_seconds"),
            "created_at": state.get("execution_started"),
            "updated_at": datetime.utcnow(),
            "iterations": state.get("iterations", 0),
            "errors": state.get("errors", [])
        }
    
    def validate_input(self, state: AgentState) -> bool:
        """Validate all required inputs are present"""
        required = ["alert", "playbook", "audit_result"]
        return all(key in state for key in required)
