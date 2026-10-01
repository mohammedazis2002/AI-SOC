"""
Reasoning Agent - Two-Phase Investigation and Synthesis
Phase 1: Investigate attack with Qdrant context + logs → Hypotheses + ML plan
Phase 2: Synthesize ML evidence → Final reasoning package
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Any

from ..agents.base_agent import BaseAgent
from ..workflows.state import AgentState
from ..tools.qdrant_search import qdrant_search
from ..tools.log_retrieval import log_retrieval
from ..config.llm_service import llm_service


class ReasoningAgent(BaseAgent):
    """
    Reasoning Agent - Investigates incidents and synthesizes evidence.
    
    Two-phase operation:
    1. Phase 1 (Investigation): Analyze alert + Qdrant context + logs → Hypotheses + ML plan
    2. Phase 2 (Synthesis): Analyze ML results → Final reasoning package
    """
    
    def __init__(self):
        super().__init__("Reasoning Agent")
        self.phase = None  # Will be set during execution
    
    async def execute(self, state: AgentState) -> AgentState:
        """
        Execute reasoning based on current phase.
        
        Phase 1:If 'ml_results' not in state, and 'reasoning_synthesis' not completed
        
        Phase 2: If 'ml_results' in state
        """
        # Determine phase
        if "ml_results" in state and "reasoning_synthesis" not in state:
            # Phase 2: Synthesis
            return await self._execute_phase_2(state)
        elif "reasoning_hypothesis" not in state:
            # Phase 1: Investigation
            return await self._execute_phase_1(state)
        else:
            # Already completed both phases
            self.log_info("Reasoning already complete, skipping")
            return state
    
    async def _execute_phase_1(self, state: AgentState) -> AgentState:
        """
        Phase 1: Investigation
        
        Steps:
        1. Search Qdrant for similar incidents
        2. Decide if logs are needed
        3. Retrieve logs if needed
        4. Generate hypotheses using LLM
        5. Create ML service plan
        """
        self.log_info("=== Phase 1: Investigation ===")
        
        alert = state["alert"]
        
        # Step 1: Fetch full KB context from all 4 collections (parallel async)
        self.log_info("Fetching KB context: incidents + playbooks + D3FEND + compliance")
        kb_context = await qdrant_search.get_full_context(alert)
        
        similar_incidents = [
            {
                "incident_id":     inc.incident_id,
                "summary":         inc.summary,
                "mitre_technique": inc.mitre_technique,
                "resolution":      inc.resolution,
                "outcome":         inc.outcome,
            }
            for inc in kb_context.similar_incidents
        ]
        
        state["qdrant_context"] = {
            "similar_incidents":   similar_incidents,
            "defensive_measures":  [
                {"name": m.name, "category": m.category, "description": m.description[:200]}
                for m in kb_context.defensive_measures
            ],
            "compliance_count":    len(kb_context.compliance_controls),
            "playbooks_count":     len(kb_context.playbooks),
            "count": len(similar_incidents),
            "searched_at": datetime.utcnow()
        }
        # Store full context for Phase 2 synthesis
        state["kb_context"] = kb_context
        
        if kb_context.retrieval_errors:
            self.log_info(f"KB retrieval warnings: {kb_context.retrieval_errors}")
        self.log_info(
            f"KB context: {len(kb_context.defensive_measures)} D3FEND measures, "
            f"{len(similar_incidents)} incidents, {len(kb_context.playbooks)} playbooks, "
            f"{len(kb_context.compliance_controls)} compliance controls"
        )
        
        # Step 2: Log retrieval
        needs_logs = self._needs_log_retrieval(alert)
        if needs_logs:
            self.log_info("Retrieving logs for investigation")
            logs = await log_retrieval.retrieve_logs_for_alert(
                alert=alert, lookback_hours=24, limit=100
            )
            state["logs_retrieved"] = logs
        else:
            self.log_info("Log retrieval not required")
            state["logs_retrieved"] = None
        
        # Step 3: Generate hypotheses with enriched KB context
        self.log_info("Generating attack hypotheses with LLM (Llama 3.1 70B)")
        
        hypothesis_prompt = self._build_hypothesis_prompt(
            alert,
            similar_incidents,
            state.get("logs_retrieved"),
            kb_context=kb_context,
        )
        
        try:
            llm_response = await llm_service.ainvoke(
                prompt=hypothesis_prompt,
                tier="primary",
                system_message="You are a cybersecurity analyst investigating a security incident. Provide concise, structured analysis."
            )
            
            hypothesis = self._parse_hypothesis_response(llm_response.content)
            state["reasoning_hypothesis"] = hypothesis
            state["timestamp_reasoning_p1"] = datetime.utcnow()
            
            ml_plan = self._create_ml_plan(hypothesis, alert)
            state["ml_plan"] = ml_plan
            self.log_info(f"Phase 1 complete: {len(ml_plan)} ML services planned")
            
        except Exception as e:
            self.log_error(f"LLM error in Phase 1: {e}", exc_info=True)
            state["reasoning_hypothesis"] = self._fallback_hypothesis(alert)
            state["ml_plan"] = ["anomaly_detection", "attack_stage", "fp_detection"]
            state["timestamp_reasoning_p1"] = datetime.utcnow()
        
        return state
    
    async def _execute_phase_2(self, state: AgentState) -> AgentState:
        """
        Phase 2: Synthesis
        
        Steps:
        1. Analyze ML results
        2. Synthesize all evidence (alert + context + logs + ML)
        3. Generate final reasoning package
        """
        self.log_info("=== Phase 2: Synthesis ===")
        
        alert = state["alert"]
        hypothesis = state.get("reasoning_hypothesis", {})
        ml_results = state["ml_results"]
        qdrant_context = state.get("qdrant_context", {})
        
        # Build synthesis prompt
        self.log_info("Synthesizing all evidence with LLM (Llama 3.1 70B)")
        
        synthesis_prompt = self._build_synthesis_prompt(
            alert,
            hypothesis,
            ml_results,
            qdrant_context,
            kb_context=state.get("kb_context"),
        )
        
        try:
            llm_response = await llm_service.ainvoke(
                prompt=synthesis_prompt,
                tier="primary",  # Use 70B for complex synthesis
                system_message="You are a senior cybersecurity analyst synthesizing evidence. Provide a comprehensive, actionable assessment."
            )
            
            # Parse synthesis
            reasoning_synthesis = self._parse_synthesis_response(llm_response.content)
            
            state["reasoning_synthesis"] = reasoning_synthesis
            state["timestamp_reasoning_p2"] = datetime.utcnow()
            
            self.log_info("Phase 2 complete: Evidence synthesized")
            
        except Exception as e:
            self.log_error(f"LLM error in Phase 2: {e}", exc_info=True)
            # Fallback synthesis
            state["reasoning_synthesis"] = self._fallback_synthesis(alert, ml_results)
            state["timestamp_reasoning_p2"] = datetime.utcnow()
        
        return state
    
    def _needs_log_retrieval(self, alert: Dict[str, Any]) -> bool:
        """Determine if logs are needed for investigation"""
        # Always retrieve logs for now
        # Future: Make this intelligent based on alert type
        return True
    
    def _build_hypothesis_prompt(
        self,
        alert: Dict[str, Any],
        similar_incidents: list,
        logs: Dict[str, Any],
        kb_context=None,
    ) -> str:
        """Build prompt for hypothesis generation with full KB context."""
        
        # Format D3FEND defensive measures
        defenses_text = "None available"
        if kb_context and kb_context.defensive_measures:
            defenses_text = "\n".join(
                f"  - [{m.category}] {m.name}: {m.description[:120]}"
                for m in kb_context.defensive_measures[:6]
            )
        
        # Format compliance violations summary
        compliance_text = "None applicable"
        if kb_context and kb_context.compliance_controls:
            by_fw = kb_context.compliance_by_framework()
            compliance_text = ", ".join(
                f"{fw} ({len(ctrls)} controls)"
                for fw, ctrls in list(by_fw.items())[:5]
            )
        
        prompt = f"""Analyze this security alert and generate attack hypotheses.

**ALERT:**
- Attack Type: {alert.get('attack_type', 'Unknown')}
- Severity: {alert.get('severity', 'Unknown')}
- Asset: {alert.get('asset_id', 'Unknown')}
- MITRE Techniques: {', '.join(alert.get('mitre_techniques', [])[:3])}
- Description: {alert.get('description', 'No description')}

**SIMILAR PAST INCIDENTS:** {len(similar_incidents)} found
{self._format_similar_incidents(similar_incidents)}

**KNOWN DEFENSIVE MEASURES (D3FEND + ATT&CK):**
{defenses_text}

**APPLICABLE COMPLIANCE FRAMEWORKS:** {compliance_text}

**LOGS:** {'Retrieved' if logs and logs.get('count', 0) > 0 else 'Not available'}

**TASK:**
Generate 2-3 attack hypotheses and recommend ML services to invoke.

**OUTPUT FORMAT (JSON):**
{{
    "hypotheses": [
        {{"description": "...", "confidence": 0.8, "evidence": ["..."]}},
        {{"description": "...", "confidence": 0.6, "evidence": ["..."]}}
    ],
    "attack_stage": "reconnaissance/initial_access/execution/persistence/lateral_movement/exfiltration",
    "threat_level": "low/medium/high/critical",
    "ml_services_needed": ["anomaly_detection", "attack_stage", ...]
}}

Respond ONLY with valid JSON, no explanation."""
        
        return prompt
    
    def _build_synthesis_prompt(
        self,
        alert: Dict[str, Any],
        hypothesis: Dict[str, Any],
        ml_results: Dict[str, Any],
        qdrant_context: Dict[str, Any],
        kb_context=None,
    ) -> str:
        """Build prompt for evidence synthesis including compliance violations."""
        
        # Compliance violations section
        compliance_section = ""
        if kb_context and kb_context.compliance_controls:
            by_fw = kb_context.compliance_by_framework()
            lines = []
            for fw, controls in by_fw.items():
                ctrl_list = ", ".join(f"{c.control_id} ({c.control_name[:40]})" for c in controls[:3])
                lines.append(f"  {fw}: {ctrl_list}")
            compliance_section = "\n".join(lines)
        else:
            compliance_section = "  None identified"
        
        prompt = f"""Synthesize all evidence into a comprehensive incident assessment.

**ALERT:**
- Type: {alert.get('attack_type')}
- Severity: {alert.get('severity')}

**INITIAL HYPOTHESES:**
{json.dumps(hypothesis.get('hypotheses', []), indent=2)}

**ML ANALYSIS RESULTS:**
{self._format_ml_results(ml_results)}

**HISTORICAL CONTEXT:**
{len(qdrant_context.get('similar_incidents', []))} similar incidents found

**COMPLIANCE VIOLATIONS IDENTIFIED:**
{compliance_section}

**TASK:**
Synthesize all evidence into final assessment.

**OUTPUT FORMAT (JSON):**
{{
    "final_assessment": "...",
    "attack_type":  "...",
    "attack_stage": "...",
    "confidence": 0.95,
    "key_indicators": ["...", "..."],
    "affected_systems": ["..."],
    "attacker_objective": "...",
    "recommended_actions": ["...", "..."],
    "escalation_needed": true,
    "reasoning": "..."
}}

Respond ONLY with valid JSON."""
        
        return prompt
    
    def _format_similar_incidents(self, incidents: list) -> str:
        """Format similar incidents for prompt"""
        if not incidents:
            return "None found"
        
        formatted = []
        for i, inc in enumerate(incidents[:3], 1):
            formatted.append(f"{i}. {inc.get('summary', 'No summary')}")
        
        return "\n".join(formatted)
    
    def _format_ml_results(self, ml_results: Dict[str, Any]) -> str:
        """Format ML results for prompt"""
        results = ml_results.get("results", {})
        
        formatted = []
        for service, result in results.items():
            if result.get("status") == "success":
                formatted.append(
                    f"- {service}: {json.dumps(result.get('result', {}))}"
                )
            else:
                formatted.append(f"- {service}: FAILED")
        
        return "\n".join(formatted) if formatted else "No ML results available"
    
    def _parse_hypothesis_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM hypothesis response"""
        try:
            # Try to extract JSON
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                raise ValueError("No JSON found in response")
        except Exception as e:
            self.log_error(f"Failed to parse hypothesis: {e}")
            return {
                "hypotheses": [{"description": "Parse error", "confidence": 0.5}],
                "ml_services_needed": ["anomaly_detection", "fp_detection"]
            }
    
    def _parse_synthesis_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM synthesis response"""
        try:
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                raise ValueError("No JSON found")
        except Exception as e:
            self.log_error(f"Failed to parse synthesis: {e}")
            return {
                "final_assessment": "Parse error",
                "confidence": 0.5,
                "escalation_needed": True
            }
    
    def _create_ml_plan(self, hypothesis: Dict[str, Any], alert: Dict[str, Any]) -> list:
        """Create ML service invocation plan"""
        # Extract services from hypothesis
        ml_services = hypothesis.get("ml_services_needed", [])
        
        # Ensure minimum services
        default_services = ["anomaly_detection", "attack_stage", "fp_detection"]
        
        for service in default_services:
            if service not in ml_services:
                ml_services.append(service)
        
        return ml_services
    
    def _fallback_hypothesis(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based fallback if LLM fails"""
        return {
            "hypotheses": [{
                "description": f"Potential {alert.get('attack_type', 'attack')} detected",
                "confidence": 0.6,
                "evidence": ["Alert triggered"]
            }],
            "attack_stage": "unknown",
            "threat_level": alert.get("severity", "medium"),
            "ml_services_needed": ["anomaly_detection", "attack_stage", "fp_detection"]
        }
    
    def _fallback_synthesis(self, alert: Dict[str, Any], ml_results: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based fallback synthesis"""
        return {
            "final_assessment": f"Security alert requires investigation: {alert.get('attack_type')}",
            "attack_type": alert.get("attack_type", "unknown"),
            "confidence": 0.5,
            "escalation_needed": True,
            "recommended_actions": ["Manual review required"]
        }
    
    def validate_input(self, state: AgentState) -> bool:
        """Validate input for reasoning agent"""
        # Phase 1: Need alert
        if "reasoning_hypothesis" not in state:
            return "alert" in state and "incident_id" in state
        
        # Phase 2: Need ML results
        if "reasoning_synthesis" not in state:
            return "ml_results" in state
        
        return True
