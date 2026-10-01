"""
LangGraph Workflow Orchestrator - Connect all agents with state management
"""

from datetime import datetime
from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from .state import AgentState
from ..agents import (
    SupervisorAgent,
    ReasoningAgent,
    PlanningAgent,
    RemediationAgent,
    AuditorAgent,
    DecisionAgent
)
from ..config.config import config
import logging

logger = logging.getLogger(__name__)


class AgenticWorkflow:
    """
    LangGraph workflow orchestrator for autonomous SOAR.
    
    Flow:
    1. Supervisor → Assess priority, delegate
    2. Reasoning P1 → Investigate (Qdrant + logs) → Hypotheses + ML plan
    3. Planning → Execute ML services in parallel
    4. Reasoning P2 → Synthesize ML results → Final assessment
    5. Remediation → Generate action plan
    6. Auditor → Verify safety + compliance
    7. Decision → Auto-execute or manual review
    
    Loop Control:
    - Max iterations: 10 (configurable)
    - Exit conditions: Decision made OR escalated OR max iterations
    """
    
    def __init__(self):
        self.logger = logging.getLogger("workflows.orchestrator")
        
        # Initialize agents
        self.supervisor = SupervisorAgent()
        self.reasoning = ReasoningAgent()
        self.planning = PlanningAgent()
        self.remediation = RemediationAgent()
        self.auditor = AuditorAgent()
        self.decision = DecisionAgent()
        
        # Build graph
        self.graph = self._build_graph()
        
        # Checkpointer for state persistence
        self.checkpointer = MemorySaver()
        
        # Compile workflow
        self.app = self.graph.compile(checkpointer=self.checkpointer)
        
        self.logger.info("AgenticWorkflow initialized")
    
    def _build_graph(self) -> StateGraph:
        """Build LangGraph workflow"""
        
        # Create graph with AgentState
        workflow = StateGraph(AgentState)
        
        # Add nodes (agents)
        workflow.add_node("supervisor", self._run_supervisor)
        workflow.add_node("reasoning_p1", self._run_reasoning_p1)
        workflow.add_node("planning", self._run_planning)
        workflow.add_node("reasoning_p2", self._run_reasoning_p2)
        workflow.add_node("remediation", self._run_remediation)
        workflow.add_node("auditor", self._run_auditor)
        # Node names must not collide with AgentState keys (e.g. "decision").
        workflow.add_node("decision_agent", self._run_decision)
        
        # Define edges (flow)
        workflow.set_entry_point("supervisor")
        
        # Supervisor → Reasoning P1
        workflow.add_edge("supervisor", "reasoning_p1")
        
        # Reasoning P1 → Planning
        workflow.add_edge("reasoning_p1", "planning")
        
        # Planning → Reasoning P2
        workflow.add_edge("planning", "reasoning_p2")
        
        # Reasoning P2 → Remediation
        workflow.add_edge("reasoning_p2", "remediation")
        
        # Remediation → Auditor
        workflow.add_edge("remediation", "auditor")
        
        # Auditor → Decision
        workflow.add_edge("auditor", "decision_agent")
        
        # Decision → END (or potentially loop back for complex cases)
        workflow.add_conditional_edges(
            "decision_agent",
            self._should_continue,
            {
                "end": END,
                "retry": "reasoning_p1"  # Loop back if needed
            }
        )
        
        return workflow
    
    async def _run_supervisor(self, state: AgentState) -> AgentState:
        """Execute Supervisor Agent"""
        self.logger.info("→ Running Supervisor Agent")
        return await self.supervisor.execute(state)
    
    async def _run_reasoning_p1(self, state: AgentState) -> AgentState:
        """Execute Reasoning Agent Phase 1 (Investigation)"""
        self.logger.info("→ Running Reasoning Agent (Phase 1: Investigation)")
        # The reasoning agent will detect it's Phase 1 based on state
        return await self.reasoning.execute(state)
    
    async def _run_planning(self, state: AgentState) -> AgentState:
        """Execute Planning Agent (ML orchestration)"""
        self.logger.info("→ Running Planning Agent")
        return await self.planning.execute(state)
    
    async def _run_reasoning_p2(self, state: AgentState) -> AgentState:
        """Execute Reasoning Agent Phase 2 (Synthesis)"""
        self.logger.info("→ Running Reasoning Agent (Phase 2: Synthesis)")
        # The reasoning agent will detect it's Phase 2 based on state
        return await self.reasoning.execute(state)
    
    async def _run_remediation(self, state: AgentState) -> AgentState:
        """Execute Remediation Agent"""
        self.logger.info("→ Running Remediation Agent")
        return await self.remediation.execute(state)
    
    async def _run_auditor(self, state: AgentState) -> AgentState:
        """Execute Auditor Agent"""
        self.logger.info("→ Running Auditor Agent")
        return await self.auditor.execute(state)
    
    async def _run_decision(self, state: AgentState) -> AgentState:
        """Execute Decision Agent"""
        self.logger.info("→ Running Decision Agent")
        return await self.decision.execute(state)
    
    def _should_continue(self, state: AgentState) -> str:
        """
        Decide whether to end or loop back for retry.
        
        Returns:
            "end" - Complete workflow
            "retry" - Loop back to reasoning for refinement
        """
        
        # Check iteration count
        iterations = state.get("iterations", 0)
        max_iterations = config.MAX_ITERATIONS
        
        if iterations >= max_iterations:
            self.logger.warning(f"Max iterations ({max_iterations}) reached, ending workflow")
            return "end"
        
        # Check decision
        decision = state.get("decision")
        
        # If we have a decision, we're done
        if decision in ["AUTO_EXECUTE", "MANUAL_REVIEW"]:
            self.logger.info(f"Decision made: {decision}, ending workflow")
            return "end"
        
        # Check if we should retry (e.g., ML services failed, need refinement)
        ml_results = state.get("ml_results", {})
        if ml_results.get("degraded") and iterations < 3:
            # Try again if ML services were degraded and we haven't retried too much
            self.logger.info("ML services degraded, retrying with different approach")
            state["iterations"] = iterations + 1
            return "retry"
        
        # Default: end
        return "end"
    
    async def process_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single alert through the entire workflow.
        
        Args:
            alert: Enriched alert dictionary
            
        Returns:
            Final state with decision and report
        """
        
        # Initialize state
        incident_id = alert.get("alert_id", f"incident_{datetime.utcnow().timestamp()}")
        
        initial_state: AgentState = {
            "incident_id": incident_id,
            "alert": alert,
            "iterations": 0,
            "execution_started": datetime.utcnow(),
            "errors": []
        }
        
        self.logger.info(f"Processing alert {incident_id}")
        
        try:
            # Run workflow
            final_state = await self.app.ainvoke(
                initial_state,
                config={"configurable": {"thread_id": incident_id}}
            )
            
            self.logger.info(f"✓ Alert {incident_id} processed successfully")
            
            return final_state
        
        except Exception as e:
            self.logger.error(f"Error processing alert {incident_id}: {e}", exc_info=True)
            
            # Return state with error
            return {
                **initial_state,
                "decision": "MANUAL_REVIEW",
                "errors": [{"error": str(e), "timestamp": datetime.utcnow()}],
                "execution_ended": datetime.utcnow()
            }
    
    async def process_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process multiple alerts in parallel.
        
        Args:
            alerts: List of enriched alerts
            
        Returns:
            List of final states
        """
        
        import asyncio
        
        self.logger.info(f"Processing batch of {len(alerts)} alerts")
        
        # Process all alerts in parallel
        tasks = [self.process_alert(alert) for alert in alerts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Batch alert {i} failed: {result}")
                final_results.append({
                    "incident_id": f"batch_{i}",
                    "error": str(result),
                    "decision": "MANUAL_REVIEW"
                })
            else:
                final_results.append(result)
        
        return final_results


# Global workflow instance
agentic_workflow = AgenticWorkflow()
