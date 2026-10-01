"""
Knowledge Base Service — MMR RAG for SOAR Agentic Layer
========================================================
4 Qdrant collections:
  • mitre_attack_defend  — D3FEND countermeasures + ATT&CK mitigations (direct ID lookup)
  • playbooks            — Response playbooks (MMR λ=0.7)
  • historical_incidents — Past resolved incidents (MMR λ=0.6)
  • compliance_kb        — 11 frameworks, exhaustive audit sweep (PageIndexRAG)

Entry point: kb_service.retrieve_context(alert) → KBContext
"""

from .kb_service import kb_service, KBRetrievalService
from .kb_context import KBContext

__all__ = ["kb_service", "KBRetrievalService", "KBContext"]
