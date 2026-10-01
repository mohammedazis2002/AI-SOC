"""
Planning Agent - ML Service Orchestration
Executes ML services in parallel and aggregates results
"""

from datetime import datetime
from typing import Dict, Any, List

from ..agents.base_agent import BaseAgent
from ..workflows.state import AgentState
from ..tools.ml_service_caller import ml_service_caller


class PlanningAgent(BaseAgent):
    """
    Planning Agent - Orchestrates ML service execution.
    
    Responsibilities:
    1. Extract ML plan from Reasoning Agent
    2. Execute ML services in parallel
    3. Aggregate results
    4. Handle failures gracefully
    """
    
    def __init__(self):
        super().__init__("Planning Agent")
    
    async def execute(self, state: AgentState) -> AgentState:
        """
        Execute ML services based on planning.
        
        Args:
            state: Agent state with ml_plan
            
        Returns:
            State with ml_results
        """
        self.log_info("=== Planning Agent: ML Service Orchestration ===")
        
        # Extract ML plan
        ml_plan = state.get("ml_plan", [])
        alert = state["alert"]
        
        if not ml_plan:
            self.log_warning("No ML plan provided, using default services")
            ml_plan = ["anomaly_detection", "attack_stage", "fp_detection"]
        
        self.log_info(f"Executing {len(ml_plan)} ML services in parallel")
        
        # Execute ML services in parallel
        try:
            ml_results = await ml_service_caller.call_multiple_services(
                service_names=ml_plan,
                alert=alert,
                retry_count=1  # 1 retry per service
            )
            
            state["ml_results"] = ml_results
            state["timestamp_planning"] = datetime.utcnow()
            
            # Log results summary
            successes = ml_results.get("successes", 0)
            failures = ml_results.get("failures", 0)
            
            self.log_info(
                f"ML services complete: {successes} succeeded, {failures} failed"
            )
            
            # Check if we have enough results to proceed
            if successes == 0:
                self.log_error("All ML services failed!")
                state["ml_results"]["degraded"] = True
                state["ml_results"]["escalation_reason"] = "All ML services unavailable"
            elif failures > 0:
                self.log_warning(f"{failures} ML services failed, proceeding with partial results")
                state["ml_results"]["degraded"] = True
                state["ml_results"]["escalation_reason"] = f"{failures} services unavailable"
            else:
                state["ml_results"]["degraded"] = False
            
        except Exception as e:
            self.log_error(f"Error executing ML services: {e}", exc_info=True)
            # Create error response
            state["ml_results"] = {
                "status": "error",
                "error": str(e),
                "services_called": ml_plan,
                "successes": 0,
                "failures": len(ml_plan),
                "degraded": True,
                "escalation_reason": "ML service execution failed"
            }
            state["timestamp_planning"] = datetime.utcnow()
        
        return state
    
    def validate_input(self, state: AgentState) -> bool:
        """Validate that ML plan exists"""
        # Check for ml_plan or use default
        if "ml_plan" in state:
            return True
        
        # ML plan is optional - we can use defaults
        self.log_warning("No ML plan in state, will use defaults")
        return True
    
    def _get_default_ml_services(self) -> List[str]:
        """Get default ML services if no plan provided"""
        return [
            "anomaly_detection",
            "attack_stage",
            "fp_detection"
        ]
