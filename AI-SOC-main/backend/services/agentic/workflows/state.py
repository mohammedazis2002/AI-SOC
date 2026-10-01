"""
Agent State Definition - Shared state across all agents
Uses TypedDict for type safety in LangGraph workflow
"""

from typing import TypedDict, Dict, List, Optional, Any
from datetime import datetime


class AgentState(TypedDict, total=False):
    """
    Shared state that flows through the entire agent pipeline.
    
    Flow progression:
    1. Supervisor → adds priority, delegation info
    2. Reasoning (P1) → adds hypotheses, ml_plan, context
    3. Planning → adds ml_results
    4. Reasoning (P2) → adds reasoning_synthesis
    5. Remediation → adds playbook
    6. Verification → adds verification result
    7. Decision → adds decision, report
    """
    
    # ==================== INPUT ====================
    alert: Dict[str, Any]                    # Enriched alert from correlation engine
    incident_id: str                         # Unique incident identifier
    priority: str                            # P1, P2, P3, P4
    
    # ==================== AGENT OUTPUTS ====================
    
    # Supervisor outputs
    delegated_to: str                        # Which agent to execute next
    timestamp_supervisor: datetime           # When supervisor processed
    
    # Reasoning Agent Phase 1 outputs
    qdrant_context: Dict[str, Any]    # Historical incidents from Qdrant
    logs_retrieved: Optional[Dict[str, Any]]  # Logs (if requested)
    reasoning_hypothesis: Dict[str, Any]      # Attack hypotheses
    ml_plan: List[str]                       # ML services to invoke
    timestamp_reasoning_p1: datetime          # Phase 1 completion time
    
    # Planning Agent outputs
    ml_results: Dict[str, Any]               # Aggregated ML service results
    timestamp_planning: datetime              # Planning completion time
    
    # Reasoning Agent Phase 2 outputs
    reasoning_synthesis: Dict[str, Any]       # Comprehensive reasoning package
    timestamp_reasoning_p2: datetime          # Phase 2 completion time
    
    # Remediation Agent outputs
    playbook: Dict[str, Any]                 # Customized action plan
    timestamp_remediation: datetime           # Remediation completion time
    
    # Verification Agent outputs
    verification: Dict[str, Any]             # Verification result
    timestamp_verification: datetime          # Verification completion time
    
    # Compliance Agent outputs (optiona)
    compliance_report: Optional[Dict[str, Any]]  # Compliance report (if triggered)
    timestamp_compliance: Optional[datetime]      # Compliance completion time
    
    # Correlation Engine outputs (added by alert pipeline before agent workflow)
    correlation_metadata: Optional[Dict[str, Any]]   # Quick correlation results
    incident_id: Optional[str]                        # Linked incident if found
    
    # Decision Engine outputs
    decision: str                            # AUTO_EXECUTE or MANUAL_REVIEW
    report: Dict[str, Any]                   # Comprehensive incident report
    timestamp_decision: datetime              # Decision completion time
    
    # ==================== METADATA ====================
    messages: List[str]                      # Agent communication messages
    iterations: int                          # Loop counter (for safety)
    errors: List[str]                        # Error log
    
    # Execution tracking
    execution_started: datetime
    execution_ended: Optional[datetime]
    total_processing_time_seconds: Optional[float]


# Type aliases for clarity
Alert = Dict[str, Any]
Playbook = Dict[str, Any]
VerificationResult = Dict[str, Any]
MLResults = Dict[str, Any]
ReasoningPackage = Dict[str, Any]
