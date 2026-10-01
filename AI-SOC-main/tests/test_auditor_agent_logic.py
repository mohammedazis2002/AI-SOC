import asyncio
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure backend matches structure
sys.modules['backend.services.agentic.config.config'] = MagicMock()
sys.modules['backend.services.agentic.config.llm_service'] = MagicMock()

# Mock imports for Auditor Agent
with patch.dict(sys.modules, {
    'backend.services.agentic.agents.base_agent': MagicMock(),
    'backend.services.agentic.workflows.state': MagicMock(),
    'backend.services.agentic.agents.audit_knowledge_base': MagicMock(),
}):
    # We need to manually load the class from the file content if we can't import due to complex deps
    # But since we fixed the imports in previous step, let's try direct import
    # Wait, previous test failed due to 'orchestrator'. Let's avoid that dependency tree.
    pass

# Let's try to import the agent directly, assuming sys.path is set correctly by previous runs
import os
sys.path.append(os.getcwd())

from backend.services.agentic.agents.auditor_agent import AuditorAgent
# Import the actual KB variables to mock them or use them
from backend.services.agentic.agents.audit_knowledge_base import CIA_CONTEXT_RULES, CIA_IMPACT_MAPPING, SAFE_ACTIONS

class TestAuditorLogic:
    def test_cia_context_override(self):
        agent = AuditorAgent()
        
        # Scenario 1: Default Auth Failure (Brute Force suspected) -> Confidentiality
        alert_default = {
            "class_uid": "3002",
            "message": "Authentication failed for user admin"
        }
        playbook = {"actions": []}
        
        # We need to patch the global variables in the AGENT module, not just local
        with patch('backend.services.agentic.agents.auditor_agent.CIA_CONTEXT_RULES', CIA_CONTEXT_RULES):
            with patch('backend.services.agentic.agents.auditor_agent.CIA_IMPACT_MAPPING', CIA_IMPACT_MAPPING):
                 with patch('backend.services.agentic.agents.auditor_agent.SAFE_ACTIONS', SAFE_ACTIONS):
                    result_default = agent._verify_cia_triad(playbook, alert_default)
        
        print(f"Scenario 1 (Default): {result_default['primary_risk']}")
        
        # Scenario 2: Context Override (High Volume/Blocked) -> Availability
        alert_override = {
            "class_uid": "3002",
            "message": "Authentication failed - account blocked due to flood"
        }
        
        with patch('backend.services.agentic.agents.auditor_agent.CIA_CONTEXT_RULES', CIA_CONTEXT_RULES):
            with patch('backend.services.agentic.agents.auditor_agent.CIA_IMPACT_MAPPING', CIA_IMPACT_MAPPING):
                 with patch('backend.services.agentic.agents.auditor_agent.SAFE_ACTIONS', SAFE_ACTIONS):
                    result_override = agent._verify_cia_triad(playbook, alert_override)
        
        print(f"Scenario 2 (Override): {result_override['primary_risk']}")
        print(f"Detail: {result_override['risk_detail']}")

if __name__ == "__main__":
    t = TestAuditorLogic()
    t.test_cia_context_override()
