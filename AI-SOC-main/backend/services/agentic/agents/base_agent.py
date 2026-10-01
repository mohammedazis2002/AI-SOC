"""
Base Agent Class - Abstract base for all autonomous agents
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import logging
from datetime import datetime

from ..workflows.state import AgentState

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Abstract base class for all autonomous agents.
    
    All agents must implement:
    - execute(): Main agent logic
    - validate_input(): Input validation
    - handle_error(): Error handling
    """
    
    def __init__(self, agent_name: str):
        """
        Initialize base agent.
        
        Args:
            agent_name: Human-readable agent name (e.g., "Supervisor", "Reasoning")
        """
        self.agent_name = agent_name
        self.logger = logging.getLogger(f"agents.{agent_name.lower().replace(' ', '_')}")
        self.execution_count = 0
        
    async def __call__(self, state: AgentState) -> AgentState:
        """
        Main entry point for agent execution.
        Handles logging, validation, error handling.
        
        Args:
            state: Current agent state
            
        Returns:
            Updated agent state
        """
        self.execution_count += 1
        self.logger.info(f"[{self.agent_name}] Starting execution (count: {self.execution_count})")
        
        try:
            # Validate input
            if not self.validate_input(state):
                raise ValueError(f"{self.agent_name}: Invalid input state")
            
            # Execute agent logic
            start_time = datetime.utcnow()
            updated_state = await self.execute(state)
            end_time = datetime.utcnow()
            
            # Add execution metrics
            execution_time = (end_time - start_time).total_seconds()
            self.logger.info(f"[{self.agent_name}] Completed in {execution_time:.2f}s")
            
            # Add message to state
            if "messages" not in updated_state:
                updated_state["messages"] = []
            updated_state["messages"].append(
                f"{self.agent_name}: Executed successfully in {execution_time:.2f}s"
            )
            
            return updated_state
            
        except Exception as e:
            self.logger.error(f"[{self.agent_name}] Error: {e}", exc_info=True)
            return await self.handle_error(state, e)
    
    @abstractmethod
    async def execute(self, state: AgentState) -> AgentState:
        """
        Main agent logic - must be implemented by subclasses.
        
        Args:
            state: Current agent state
            
        Returns:
            Updated agent state
        """
        pass
    
    def validate_input(self, state: AgentState) -> bool:
        """
        Validate input state before execution.
        Default: Check that alert and incident_id exist.
        
        Args:
            state: Input state
            
        Returns:
            True if valid, False otherwise
        """
        required_keys = ["alert", "incident_id"]
        return all(key in state for key in required_keys)
    
    async def handle_error(self, state: AgentState, error: Exception) -> AgentState:
        """
        Handle agent execution errors.
        Default: Log error and add to state.
        
        Args:
            state: Current state
            error: Exception that occurred
            
        Returns:
            State with error information
        """
        if "errors" not in state:
            state["errors"] = []
        
        error_info = {
            "agent": self.agent_name,
            "error": str(error),
            "timestamp": datetime.utcnow()
        }
        state["errors"].append(error_info)
        
        self.logger.error(f"[{self.agent_name}] Error handled: {error}")
        
        return state
    
    def log_info(self, message: str):
        """Log info message"""
        self.logger.info(f"[{self.agent_name}] {message}")
    
    def log_debug(self, message: str):
        """Log debug message"""
        self.logger.debug(f"[{self.agent_name}] {message}")
    
    def log_warning(self, message: str):
        """Log warning message"""
        self.logger.warning(f"[{self.agent_name}] {message}")
    
    def log_error(self, message: str, exc_info=False):
        """Log error message"""
        self.logger.error(f"[{self.agent_name}] {message}", exc_info=exc_info)
