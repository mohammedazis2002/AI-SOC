"""
Qdrant Search Tool - RAG interface backed by KBRetrievalService
================================================================
Maintains the original interface so all agents need zero changes.
All 3 stub methods now call through to kb_service.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from ...knowledge_base import kb_service, KBContext
from ..config.config import config

logger = logging.getLogger("tools.qdrant_search")


class QdrantSearchTool:
    """
    Qdrant Search Tool - Real RAG via KBRetrievalService.

    Collections:
    - historical_incidents : MMR λ=0.6
    - playbooks            : MMR λ=0.7
    - compliance_kb        : Exhaustive 4-stage audit sweep
    - mitre_attack_defend  : Direct ID lookup + D3FEND measures
    """

    def __init__(self):
        # kb_service owns the Qdrant client and BGE model singleton
        self._kb = kb_service
        self._context_cache: Dict[str, KBContext] = {}

    async def _get_context(self, alert: Dict[str, Any]) -> KBContext:
        """Cache context per alert_id to avoid repeated KB calls within same workflow."""
        alert_id = str(alert.get("id", alert.get("alert_id", id(alert))))
        if alert_id not in self._context_cache:
            self._context_cache[alert_id] = await self._kb.retrieve_context(alert)
        return self._context_cache[alert_id]

    # ── Public interface (unchanged signatures) ────────────────────────────────

    async def search_similar_incidents(
        self,
        alert: Dict[str, Any],
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Search for similar historical incidents (MMR λ=0.6, top-5).
        Returns list of dicts compatible with existing agent consumers.
        """
        try:
            ctx = await self._get_context(alert)
            results = []
            for inc in ctx.similar_incidents[:limit]:
                results.append({
                    "incident_id":      inc.incident_id,
                    "summary":          inc.summary,
                    "mitre_technique":  inc.mitre_technique,
                    "resolution":       inc.resolution,
                    "outcome":          inc.outcome,
                    "analyst_approved": inc.analyst_approved,
                    "timestamp":        inc.timestamp,
                    "score":            inc.mmr_score,
                })
            logger.info(f"Similar incidents: {len(results)} returned")
            return results
        except Exception as e:
            logger.error(f"Error searching incidents: {e}")
            return []

    async def search_playbooks(
        self,
        attack_type: str,
        severity: str,
        limit: int = 5,
        alert: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search for relevant playbooks (MMR λ=0.7, top-5).
        Accepts either alert dict (preferred) or attack_type+severity strings.
        """
        try:
            if alert is None:
                alert = {"technique_name": attack_type, "severity": severity}
            ctx = await self._get_context(alert)
            results = []
            for pb in ctx.playbooks[:limit]:
                results.append({
                    "playbook_id":      pb.playbook_id,
                    "title":           pb.title,
                    "trigger":         pb.trigger,
                    "steps":           pb.steps,
                    "tactic":          pb.tactic,
                    "mitre_techniques": pb.mitre_techniques,
                    "d3fend_categories": pb.d3fend_categories,
                    "score":           pb.mmr_score,
                })
            logger.info(f"Playbooks: {len(results)} returned for '{attack_type}'")
            return results
        except Exception as e:
            logger.error(f"Error searching playbooks: {e}")
            return []

    async def search_compliance_knowledge(
        self,
        framework: str,
        violation_type: str,
        limit: int = 10,
        alert: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Exhaustive compliance audit sweep (all 11 frameworks).
        `framework` and `violation_type` used to build the alert query if no alert provided.
        Returns ALL applicable controls, grouped by framework.
        """
        try:
            if alert is None:
                alert = {
                    "technique_name": violation_type,
                    "tactic_name": framework,
                }
            ctx = await self._get_context(alert)
            grouped = ctx.compliance_by_framework()
            results = []
            for fw_name, controls in grouped.items():
                for ctrl in controls:
                    results.append({
                        "framework":    ctrl.framework,
                        "control_id":  ctrl.control_id,
                        "control_name": ctrl.control_name,
                        "description": ctrl.description,
                        "parent_chain": ctrl.parent_chain,
                        "match_type":  ctrl.match_type,
                        "cia_flags":   ctrl.cia_flags,
                        "severity_weight": ctrl.severity_weight,
                    })
            logger.info(f"Compliance: {len(results)} controls across {len(grouped)} frameworks")
            return results
        except Exception as e:
            logger.error(f"Error searching compliance KB: {e}")
            return []

    async def get_defensive_measures(
        self, alert: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        NEW: Get D3FEND countermeasures + ATT&CK mitigations for alert technique.
        Called by reasoning_agent to enrich context with defensive intelligence.
        """
        try:
            ctx = await self._get_context(alert)
            return [
                {
                    "name": m.name,
                    "category": m.category,
                    "description": m.description,
                    "source": m.source,
                    "technique_id": m.technique_id,
                }
                for m in ctx.defensive_measures
            ]
        except Exception as e:
            logger.error(f"Error fetching defensive measures: {e}")
            return []

    async def get_full_context(self, alert: Dict[str, Any]) -> KBContext:
        """
        NEW: Return full KBContext for agents that can consume it directly.
        Called by reasoning_agent Phase 1 to inject full KB into LLM context.
        """
        return await self._get_context(alert)

    def clear_cache(self):
        """Clear the per-alert context cache (call after workflow completes)."""
        self._context_cache.clear()

    def _build_incident_query(self, alert: Dict[str, Any]) -> str:
        """Legacy helper — kept for compatibility."""
        parts = []
        if "attack_type" in alert:
            parts.append(f"Attack: {alert['attack_type']}")
        if "severity" in alert:
            parts.append(f"Severity: {alert['severity']}")
        if "mitre_techniques" in alert:
            parts.append(f"MITRE: {', '.join(alert['mitre_techniques'][:3])}")
        if "asset_type" in alert:
            parts.append(f"Asset: {alert['asset_type']}")
        return " | ".join(parts)


# Global instance
qdrant_search = QdrantSearchTool()
