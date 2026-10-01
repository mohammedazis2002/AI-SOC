"""
Agentic Normalisation Agent
===========================
Fully autonomous alert normaliser. No hardcoded source-specific logic.
Replaces log_processor.py + wazuh_mapper.py + sentinelone_mapper.py + ai_mapper.py.

Usage:
    from backend.services.ingestion.normalisation_agent import NormalisationAgent

    agent = NormalisationAgent(redis_client=redis, llm_client=llm)
    ulf = await agent.normalise(raw_alert)
"""

from .agent import NormalisationAgent
from .alert_id_generator import generate_alert_id

__all__ = ["NormalisationAgent", "generate_alert_id"]
