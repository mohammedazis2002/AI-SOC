import asyncio
import sys
import os

# Adjust path to import backend
sys.path.append(os.path.join(os.getcwd(), "backend"))

# Mocking config and llm_service to avoid dependencies
from unittest.mock import MagicMock
sys.modules['backend.services.agentic.config.config'] = MagicMock()
sys.modules['backend.services.agentic.config.llm_service'] = MagicMock()

# Mock the config values
sys.modules['backend.services.agentic.config.config'].config.COMPLIANCE_FRAMEWORKS = ["GDPR", "PCI_DSS"]
sys.modules['backend.services.agentic.config.config'].config.AUTO_EXECUTE_BLACKLIST = ["shutdown"]

# Now import the agent
from backend.services.agentic.agents.auditor_agent import AuditorAgent

async def test_auditor():
    agent = AuditorAgent()
    
    # 1. Mock Alert with ENRICHMENT Data
    alert = {
        "class_uid": "3001", # Account Compromise (Confidentiality Risk)
        "message": "User account compromised",
        "enrichment": {
            "has_pii": True,       # Triggers GDPR
            "has_pci": False,
            "risk_score": 85
        }
    }
    
    # 2. Mock Playbook with MISSING Action (No Notify DPO)
    playbook = {
        "actions": [
            {"action_type": "disable_user", "target": "user123", "rollback": "enable_user"},
            {"action_type": "investigate", "target": "logs", "rollback": "N/A"}
        ]
    }
    
    state = {
        "alert": alert,
        "playbook": playbook
    }
    
    print("\n--- Running Auditor Agent Test ---")
    
    # Mock LLM response for solution generation
    mock_llm_response = MagicMock()
    mock_llm_response.content = '{"action": {"action_type": "notify_dpo", "step": 3}, "explanation": "Mock LLM Solution", "compliance_met": true}'
    agent.llm_service.ainvoke = MagicMock(return_value=mock_llm_response) # Mocking the async call
    
    # Needs to mock the import inside the file if we want to run it directly without full env
    # But since we set sys.modules, it should work if we didn't miss anything.
    
    # Mocking the llm_service import inside auditor_agent is tricky because it's already imported.
    # We rely on the sys.modules patch above.
    
    # Run Execute
    # Since execute is async and calls llm_service.ainvoke
    try:
        # We need to ensure llm_service is actually the mock we created
        import backend.services.agentic.config.llm_service as llm_service_module
        llm_service_module.llm_service.ainvoke = MagicMock(return_value=mock_llm_response)
        
        # NOTE: Since ainvoke is async, the return_value must be an AWAITABLE
        f = asyncio.Future()
        f.set_result(mock_llm_response)
        llm_service_module.llm_service.ainvoke.return_value = f

        result_state = await agent.execute(state)
        
        audit = result_state["audit_result"]
        
        print(f"\n[CIA Triad]")
        print(f"Primary Risk: {audit['cia_triad']['primary_risk']}")
        print(f"Risk Detail: {audit['cia_triad']['risk_detail']}")
        print(f"Confidentiality Status: {audit['cia_triad']['confidentiality']['status']}")
        print(f"Confidentiality Details: {audit['cia_triad']['confidentiality']['details']}")
        
        print(f"\n[Compliance]")
        print(f"Violations Found: {audit['compliance']['violations_found']}")
        if audit['compliance']['violations']:
            for v in audit['compliance']['violations']:
                print(f"Violation: {v['framework']} - {v['requirement']}")
                print(f"Issue: {v['issue']}")
            
        print(f"\n[Decision]")
        print(f"Final Decision: {audit['decision']}")
        
    except Exception as e:
        print(f"Test Failed: {e}")
        import traceback
        with open("test_error.log", "w") as f:
            traceback.print_exc(file=f)

if __name__ == "__main__":
    asyncio.run(test_auditor())
