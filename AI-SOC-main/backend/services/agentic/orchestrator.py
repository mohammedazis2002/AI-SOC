"""
Compatibility shim.

Older imports expect `backend.services.agentic.orchestrator.AgenticOrchestrator`.
The workflow implementation lives in `backend.services.agentic.workflows.orchestrator`.
"""

from __future__ import annotations

from .workflows.orchestrator import AgenticWorkflow as AgenticOrchestrator

__all__ = ["AgenticOrchestrator"]

