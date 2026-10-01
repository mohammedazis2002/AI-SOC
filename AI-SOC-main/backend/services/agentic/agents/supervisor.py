"""
Supervisor Agent - Task Delegation and Workflow Initiation
Simplest agent: Receives alert and delegates to Reasoning Agent
"""

from datetime import datetime
from ..agents.base_agent import BaseAgent
from ..workflows.state import AgentState


class SupervisorAgent(BaseAgent):
    """
    Supervisor Agent - Entry point for autonomous incident response.
    
    Responsibilities:
    1. Receive enriched alert
    2. Assess priority based on severity
    3. Delegate to Reasoning Agent
    4. Add metadata to state
    """
    
    def __init__(self):
        super().__init__("Supervisor")
    
    async def execute(self, state: AgentState) -> AgentState:
        """
        Execute supervisor logic: assess priority and delegate.
        
        Args:
            state: Agent state with alert and incident_id
            
        Returns:
            Updated state with priority and delegation info
        """
        alert = state["alert"]
        
        self.log_info(f"Received alert: {alert.get('alert_id', 'unknown')}")
        
        # Assess priority based on severity
        priority = self._assess_priority(alert)
        self.log_info(f"Assessed priority: {priority}")
        
        # Add metadata to state
        state["priority"] = priority
        state["delegated_to"] = "reasoning_agent"
        state["timestamp_supervisor"] = datetime.utcnow()
        
        # Initialize metadata if not present
        if "messages" not in state:
            state["messages"] = []
        if "iterations" not in state:
            state["iterations"] = 0
        if "errors" not in state:
            state["errors"] = []
        
        # Add execution start time
        if "execution_started" not in state:
            state["execution_started"] = datetime.utcnow()
        
        self.log_info(f"Delegating to Reasoning Agent with priority {priority}")
        
        return state
    
    def _assess_priority(self, alert: dict) -> str:
        """
        Assess priority based on alert severity.
        
        Args:
            alert: Enriched alert dictionary
            
        Returns:
            Priority string (P1, P2, P3, P4)
        """
        severity = alert.get("severity", "medium").lower()
        
        priority_map = {
            "critical": "P1",
            "high": "P2",
            "medium": "P3",
            "low": "P4"
        }
        
        priority = priority_map.get(severity, "P3")
        
        # Additional factors can increase priority
        if alert.get("asset_criticality") == "critical":
            # Bump up one level
            if priority == "P4":
                priority = "P3"
            elif priority == "P3":
                priority = "P2"
            elif priority == "P2":
                priority = "P1"
        
        return priority
    
    def validate_input(self, state: AgentState) -> bool:
        """
        Validate that state has required fields for supervisor.
        
        Args:
            state: Input state
            
        Returns:
            True if valid
        """
        required_keys = ["alert", "incident_id"]
        
        if not all(key in state for key in required_keys):
            self.log_error(f"Missing required keys: {required_keys}")
            return False
        
        alert = state["alert"]
        
        # Validate alert has minimum fields
        if not isinstance(alert, dict):
            self.log_error("Alert must be a dictionary")
            return False
        
        if "alert_id" not in alert and "id" not in alert:
            self.log_warning("Alert missing alert_id or id field")
        
        return True
