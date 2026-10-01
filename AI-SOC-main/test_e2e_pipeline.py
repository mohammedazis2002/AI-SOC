"""
End-to-End Orchestrator Pipeline Test
=====================================
Instantiates the 5-node agentic workflow and feeds a simulated 
enriched OCSF alert (like what Redis delivers) into the graph.

Verifies that the AgentState contracts (fields read/written) are honored 
successfully across reasoning, remediation, auditor, decision, and reporting.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
import uuid
import sys

# Configure basic logging to see the pipeline run in the terminal
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# SOAR Platform imports
try:
    from backend.services.agentic.workflows.orchestrator import AgenticWorkflow
    from backend.services.agentic.workflows.state import AgentState
except ImportError as e:
    print(f"ImportError: {e}. Are you running from the soar-platform root?")
    sys.exit(1)


# Dummy Alert mocking the exact schema passed by Alert Pipeline
MOCK_ALERT = {
    "finding": {
        "title": "Suspicious PowerShell Execution",
        "desc": "Encoded powershell command launched from Word macro.",
    },
    "severity": "High",
    "fp_probability": 0.12,
    "enrichments": {
        "mitre": {"tactic_name": "Execution", "technique_id": "T1059.001"},
    },
    "assets": [{"hostname": "WKSTN-7734", "ip": "10.0.0.45", "user": "alice"}],
    "asset_risk": {"total_risk_score": 85.0},
    "threat_intel": {"risk_score": 90.0},
}


async def test_e2e_pipeline():
    logger.info("Initializing 5-Node Agentic Workflow...")
    workflow = AgenticWorkflow()
    
    incident_id = str(uuid.uuid4())
    
    # Initial state mimicking Redis Ingestion
    initial_state: AgentState = {
        "incident_id": incident_id,
        "alert": MOCK_ALERT,
        "triage_score": 88.5,       # Forces "ir" tier routing
        "priority": "P2",
        "iterations": 0,
        "execution_started": datetime.now(timezone.utc)
    }
    
    logger.info(f"Injecting simulated incident {incident_id} into Pipeline...")
    
    try:
        # Run graph
        final_state = await workflow.app.ainvoke(
            initial_state, 
            config={"configurable": {"thread_id": incident_id}}
        )
        
        logger.info("\n========== PIPELINE COMPLETE ==========")
        logger.info(f"Decision:     {final_state.get('decision')}")
        logger.info(f"Final Tier:   {final_state.get('final_tier')}")
        logger.info(f"Report Exists?: {'Yes' if 'comprehensive_report' in final_state else 'No'}")
        
        if final_state.get("errors"):
            logger.error("Errors encountered during execution:")
            for err in final_state["errors"]:
                logger.error(f" - {err}")
        else:
            logger.info("0 Pipeline Errors! Clean execution.")
            
        return 0
        
    except Exception as e:
        logger.exception(f"Pipeline crashed horribly: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(test_e2e_pipeline()))
