"""
Remediation Agent - Creates action plans from playbooks
Customizes response actions based on incident context
"""

import json
from datetime import datetime
from typing import Dict, Any, List

from ..agents.base_agent import BaseAgent
from ..workflows.state import AgentState
from ..tools.qdrant_search import qdrant_search
from ..config.llm_service import llm_service


class RemediationAgent(BaseAgent):
    """
    Remediation Agent - Generates customized action plans.
    
    Responsibilities:
    1. Search for relevant playbooks
    2. Customize actions based on incident context
    3. Generate step-by-step remediation plan
    4. Include rollback procedures
    """
    
    def __init__(self):
        super().__init__("Remediation Agent")
    
    async def execute(self, state: AgentState) -> AgentState:
        """
        Generate remediation playbook.
        
        Args:
            state: Agent state with reasoning_synthesis
            
        Returns:
            State with playbook
        """
        self.log_info("=== Remediation Agent: Action Planning ===")
        
        alert = state["alert"]
        reasoning = state.get("reasoning_synthesis", {})
        
        # Extract key info
        attack_type = reasoning.get("attack_type", alert.get("attack_type", "unknown"))
        severity = alert.get("severity", "medium")
        
        # Step 1: Search for relevant playbooks (pass full alert for technique_id-aware MMR)
        self.log_info(f"Searching playbooks for {attack_type} (technique={alert.get('technique_id', 'unknown')})")
        
        playbooks = await qdrant_search.search_playbooks(
            attack_type=attack_type,
            severity=severity,
            limit=5,        # plan specifies top-5 MMR-diverse playbooks
            alert=alert,    # enables technique_id + tactic + asset_type context
        )
        
        # Step 2: Generate customized action plan with LLM
        self.log_info("Generating customized action plan (Llama 3.1 8B)")
        
        try:
            remediation_prompt = self._build_remediation_prompt(
                alert,
                reasoning,
                playbooks
            )
            
            llm_response = await llm_service.ainvoke(
                prompt=remediation_prompt,
                tier="secondary",  # Use 8B for faster action planning
                system_message="You are a security engineer creating incident remediation plans. Be specific and actionable."
            )
            
            # Parse response
            playbook = self._parse_playbook_response(llm_response.content)
            
            state["playbook"] = playbook
            state["timestamp_remediation"] = datetime.utcnow()
            
            self.log_info(f"Generated playbook with {len(playbook.get('actions', []))} actions")
            
        except Exception as e:
            self.log_error(f"LLM error generating playbook: {e}", exc_info=True)
            # Fallback to template-based playbook
            state["playbook"] = self._fallback_playbook(attack_type, severity)
            state["timestamp_remediation"] = datetime.utcnow()
        
        return state
    
    def _build_remediation_prompt(
        self,
        alert: Dict[str, Any],
        reasoning: Dict[str, Any],
        playbooks: List[Dict[str, Any]]
    ) -> str:
        """Build prompt for remediation plan generation"""

        # Format KB playbook content for the LLM
        if playbooks:
            pb_lines = []
            for i, pb in enumerate(playbooks[:3], 1):
                steps_preview = "\n    ".join(pb.get("steps", [])[:4])
                pb_lines.append(
                    f"  [{i}] {pb.get('title', 'Untitled')} "
                    f"(MMR score={pb.get('score', 0):.2f})\n"
                    f"  Trigger: {pb.get('trigger', '')}\n"
                    f"  Steps:\n    {steps_preview}"
                )
            playbooks_text = "\n\n".join(pb_lines)
        else:
            playbooks_text = "  No playbooks found in KB — use general best practices."
        
        prompt = f"""Create a remediation action plan for this security incident.

**INCIDENT DETAILS:**
- Attack Type: {alert.get('attack_type')}
- Severity: {alert.get('severity')}
- Asset: {alert.get('asset_id')}
- MITRE Technique: {alert.get('technique_id', 'Unknown')} — {alert.get('technique_name', '')}
- Tactic: {alert.get('tactic_name', alert.get('tactic', 'Unknown'))}
- User: {alert.get('user', 'N/A')}

**ANALYSIS:**
{reasoning.get('final_assessment', 'No assessment')}

**RECOMMENDED ACTIONS (from analysis):**
{json.dumps(reasoning.get('recommended_actions', []), indent=2)}

**REFERENCE PLAYBOOKS FROM KB (MMR-diverse top-{len(playbooks)}):**
{playbooks_text}

**TASK:**
Create a detailed, step-by-step remediation plan that builds on the reference playbooks above.
Preserve the diversity of approaches shown. Be specific and actionable.

**OUTPUT FORMAT (JSON):**
{{
    "objective": "...",
    "actions": [
        {{
            "step": 1,
            "action_type": "isolate/block/disable/investigate/...",
            "target": "asset/ip/user/...",
            "command": "<specific command or API call>",
            "expected_result": "...",
            "rollback": "..."
        }},
        ...
    ],
    "priority": "immediate/high/medium",
    "estimated_time_minutes": 15,
    "requires_approval": true/false,
    "rollback_plan": ["...", "..."],
    "validation_steps": ["...", "..."]
}}

Respond ONLY with valid JSON. Be specific and actionable."""
        
        return prompt

    
    def _parse_playbook_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM playbook response"""
        try:
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                playbook = json.loads(json_match.group())
                # Add metadata
                playbook["generated_by"] = "llm"
                playbook["generated_at"] = datetime.utcnow().isoformat()
                return playbook
            else:
                raise ValueError("No JSON found")
        except Exception as e:
            self.log_error(f"Failed to parse playbook: {e}")
            return self._fallback_playbook("unknown", "medium")
    
    def _fallback_playbook(self, attack_type: str, severity: str) -> Dict[str, Any]:
        """Template-based fallback playbook"""
        
        # Basic containment actions
        actions = [
            {
                "step": 1,
                "action_type": "investigate",
                "target": "alert_details",
                "command": "Review alert context",
                "expected_result": "Understanding of threat",
                "rollback": "N/A"
            },
            {
                "step": 2,
                "action_type": "isolate",
                "target": "affected_asset",
                "command": "Quarantine asset from network",
                "expected_result": "Asset isolated",
                "rollback": "Re-enable network access"
            },
            {
                "step": 3,
                "action_type": "collect_evidence",
                "target": "logs_and_files",
                "command": "Preserve forensic evidence",
                "expected_result": "Evidence collected",
                "rollback": "N/A"
            }
        ]
        
        return {
            "objective": f"Contain and investigate {attack_type} attack",
            "actions": actions,
            "priority": "high" if severity in ["high", "critical"] else "medium",
            "estimated_time_minutes": 30,
            "requires_approval": severity in ["critical", "high"],
            "rollback_plan": ["Restore asset from backup", "Re-enable services"],
            "validation_steps": ["Verify threat contained", "Check for persistence"],
            "generated_by": "fallback_template",
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def validate_input(self, state: AgentState) -> bool:
        """Validate that reasoning synthesis exists"""
        return "reasoning_synthesis" in state
