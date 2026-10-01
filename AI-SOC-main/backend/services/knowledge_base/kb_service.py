"""
KB Retrieval Service — Central Entry Point
==========================================
Single async service that queries all 4 collections in parallel and
returns a unified KBContext for the agentic pipeline.

Usage:
    from backend.services.knowledge_base import kb_service, KBContext

    ctx: KBContext = await kb_service.retrieve_context(alert)
    summary = ctx.to_agent_summary()  # pass to LLM prompts
"""

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

import numpy as np
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchAny, MatchValue
from sentence_transformers import SentenceTransformer

from .kb_context import (
    ComplianceControl, D3FendMeasure, IncidentResult, KBContext, PlaybookResult,
)
from .mmr import mmr_rerank_qdrant

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))

EMBEDDING_MODEL = "BAAI/bge-large-en-v1.5"
BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "
VECTOR_SIZE = 1024

COLL_PLAYBOOKS   = "playbooks"
COLL_INCIDENTS   = "historical_incidents"
COLL_DEFEND      = "mitre_attack_defend"
COLL_COMPLIANCE  = "compliance_kb"

# MMR parameters (per collection)
PLAYBOOK_LAMBDA     = 0.7
INCIDENT_LAMBDA     = 0.6
DEFEND_LAMBDA       = 0.6   # fallback only; direct lookup is primary

PLAYBOOK_CANDIDATES  = 20
INCIDENT_CANDIDATES  = 15
DEFEND_CANDIDATES    = 10

PLAYBOOK_TOP_K  = 5
INCIDENT_TOP_K  = 5
DEFEND_TOP_K    = 3  # direct lookup, so typically small

COMPLIANCE_PER_FRAMEWORK_LIMIT = 5   # semantic sweep cap per framework


# ── Embedding Singleton ────────────────────────────────────────────────────────
_embedder: Optional[SentenceTransformer] = None


def _get_embedder() -> SentenceTransformer:
    """Shared BGE model — loaded once, reused across all KB calls."""
    global _embedder
    if _embedder is None:
        logger.info(f"Loading embedding model: {EMBEDDING_MODEL}")
        _embedder = SentenceTransformer(EMBEDDING_MODEL)
        logger.info("Embedding model loaded.")
    return _embedder


def _embed(text: str) -> np.ndarray:
    """Embed a single query string with the BGE query prefix."""
    embedder = _get_embedder()
    return embedder.encode(BGE_QUERY_PREFIX + text, normalize_embeddings=True)


# ── KBRetrievalService ─────────────────────────────────────────────────────────
class KBRetrievalService:
    """
    Central retrieval service for the SOAR knowledge base.
    All 4 collections are queried concurrently inside retrieve_context().
    """

    def __init__(self):
        self._client: Optional[AsyncQdrantClient] = None

    def _get_client(self) -> AsyncQdrantClient:
        if self._client is None:
            self._client = AsyncQdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
        return self._client

    async def retrieve_context(self, alert: Dict[str, Any]) -> KBContext:
        """
        Main entry point. Queries all 4 collections in parallel.

        Args:
            alert: Enriched alert dict. Expected keys (all optional but improve recall):
                   technique_id, technique_name, tactic, tactic_name,
                   subtechnique_id, asset_type, severity,
                   cia_impact ({"confidentiality": bool, "integrity": bool, "availability": bool})

        Returns:
            KBContext assembled from all 4 collections.
        """
        technique_id  = alert.get("technique_id") or alert.get("mitre", {}).get("technique_id")
        technique_name = alert.get("technique_name", "")
        tactic_name    = alert.get("tactic_name", alert.get("tactic", ""))
        asset_type     = alert.get("asset_type", "")
        severity       = alert.get("severity", "medium")
        cia            = alert.get("cia_impact", {})

        ctx = KBContext(technique_id=technique_id)

        # Build query text for semantic searches (not used for direct D3FEND lookup)
        query_text = self._build_query(
            technique_id, technique_name, tactic_name, asset_type, severity, cia
        )
        logger.info(f"KB retrieval | technique={technique_id} | query={query_text[:80]}...")

        # Run all 4 retrievals concurrently
        results = await asyncio.gather(
            self._retrieve_defensive_measures(technique_id, query_text),
            self._retrieve_playbooks(query_text),
            self._retrieve_incidents(query_text),
            self._retrieve_compliance(technique_id, query_text, cia),
            return_exceptions=True,
        )

        def _handle(result, field_name: str, default):
            if isinstance(result, Exception):
                logger.error(f"KB retrieval error [{field_name}]: {result}")
                ctx.retrieval_errors.append(f"{field_name}: {result}")
                return default
            return result

        ctx.defensive_measures = _handle(results[0], "defensive_measures", [])
        ctx.playbooks          = _handle(results[1], "playbooks", [])
        ctx.similar_incidents  = _handle(results[2], "similar_incidents", [])
        ctx.compliance_controls= _handle(results[3], "compliance_controls", [])

        logger.info(
            f"KB done | defenses={len(ctx.defensive_measures)} "
            f"playbooks={len(ctx.playbooks)} incidents={len(ctx.similar_incidents)} "
            f"compliance={len(ctx.compliance_controls)}"
        )
        return ctx

    # ── MITRE ATT&CK + D3FEND ─────────────────────────────────────────────────

    async def _retrieve_defensive_measures(
        self, technique_id: Optional[str], fallback_query: str
    ) -> List[D3FendMeasure]:
        """
        Primary: direct scroll by technique_id field (O(1), deterministic).
        Fallback: semantic MMR search if technique not in index.
        """
        client = self._get_client()

        # ── Primary: direct lookup ────────────────────────────────────────────
        if technique_id:
            try:
                results, _ = await client.scroll(
                    collection_name=COLL_DEFEND,
                    scroll_filter=Filter(
                        must=[FieldCondition(key="technique_id", match=MatchValue(value=technique_id))]
                    ),
                    limit=1,
                    with_payload=True,
                    with_vectors=False,
                )
                if results:
                    return self._parse_defend_payload(results[0].payload)
            except Exception as e:
                logger.warning(f"D3FEND direct lookup failed for {technique_id}: {e}")

        # ── Fallback: semantic MMR ────────────────────────────────────────────
        if not fallback_query:
            return []
        try:
            query_emb = _embed(fallback_query)
            candidates = await client.query_points(
                collection_name=COLL_DEFEND,
                query=query_emb.tolist(),
                limit=DEFEND_CANDIDATES,
                with_vectors=True,
                with_payload=True,
            )
            ranked = mmr_rerank_qdrant(query_emb, candidates.points, k=DEFEND_TOP_K, lambda_param=DEFEND_LAMBDA)
            measures = []
            for pt in ranked:
                measures.extend(self._parse_defend_payload(pt.payload))
            return measures
        except Exception as e:
            logger.warning(f"D3FEND semantic fallback failed: {e}")
            return []

    def _parse_defend_payload(self, payload: Dict) -> List[D3FendMeasure]:
        measures = []
        # D3FEND techniques
        for tech in payload.get("d3fend_techniques", []):
            if isinstance(tech, dict):
                name = tech.get("label", tech.get("name", ""))
                desc = tech.get("definition", tech.get("description", ""))
                cat  = tech.get("category", "Unknown")
                tech_id = tech.get("id", "")
            else:
                name = str(tech)
                desc = ""
                cat  = "Unknown"
                tech_id = ""
            measures.append(D3FendMeasure(
                technique_id=tech_id, name=name, category=cat,
                description=desc, source="d3fend"
            ))
        # ATT&CK official mitigations
        for mit in payload.get("attack_mitigations", []):
            if isinstance(mit, dict):
                measures.append(D3FendMeasure(
                    technique_id=mit.get("mitigation_id", ""),
                    name=mit.get("name", ""),
                    category="ATT&CK Mitigation",
                    description=mit.get("description", ""),
                    source="attack_mitigation",
                ))
            elif isinstance(mit, str):
                measures.append(D3FendMeasure(
                    technique_id="", name=mit, category="ATT&CK Mitigation",
                    description=mit, source="attack_mitigation"
                ))
        return measures

    # ── Playbooks ──────────────────────────────────────────────────────────────

    async def _retrieve_playbooks(self, query_text: str) -> List[PlaybookResult]:
        if not query_text:
            return []
        client = self._get_client()
        query_emb = _embed(query_text)

        candidates = await client.query_points(
            collection_name=COLL_PLAYBOOKS,
            query=query_emb.tolist(),
            limit=PLAYBOOK_CANDIDATES,
            with_vectors=True,
            with_payload=True,
        )
        ranked = mmr_rerank_qdrant(
            query_emb, candidates.points, k=PLAYBOOK_TOP_K, lambda_param=PLAYBOOK_LAMBDA
        )
        results = []
        for pt in ranked:
            p = pt.payload
            results.append(PlaybookResult(
                playbook_id=p.get("playbook_id", ""),
                title=p.get("title", ""),
                trigger=p.get("trigger", ""),
                mitre_techniques=p.get("mitre_technique_ids", []),
                tactic=p.get("tactic", ""),
                steps=p.get("steps", []),
                d3fend_categories=p.get("d3fend_categories", []),
                chunk_type=p.get("chunk_type", "summary"),
                mmr_score=pt.score,
                similarity_score=p.get("original_score", pt.score),
            ))
        return results

    # ── Historical Incidents ───────────────────────────────────────────────────

    async def _retrieve_incidents(self, query_text: str) -> List[IncidentResult]:
        if not query_text:
            return []
        client = self._get_client()

        try:
            info = await client.get_collection(COLL_INCIDENTS)
            if info.points_count == 0:
                logger.info("historical_incidents collection is empty — skipping.")
                return []
        except Exception:
            return []

        query_emb = _embed(query_text)
        candidates = await client.query_points(
            collection_name=COLL_INCIDENTS,
            query=query_emb.tolist(),
            limit=INCIDENT_CANDIDATES,
            with_vectors=True,
            with_payload=True,
        )
        ranked = mmr_rerank_qdrant(
            query_emb, candidates.points, k=INCIDENT_TOP_K, lambda_param=INCIDENT_LAMBDA
        )
        results = []
        for pt in ranked:
            p = pt.payload
            results.append(IncidentResult(
                incident_id=p.get("incident_id", ""),
                summary=p.get("summary", ""),
                mitre_technique=p.get("mitre_technique", ""),
                resolution=p.get("resolution", ""),
                outcome=p.get("outcome", ""),
                analyst_approved=p.get("analyst_approved", False),
                timestamp=p.get("timestamp"),
                similarity_score=p.get("original_score", pt.score),
                mmr_score=pt.score,
            ))
        return results

    # ── Compliance KB (Exhaustive Audit Sweep) ─────────────────────────────────

    async def _retrieve_compliance(
        self,
        technique_id: Optional[str],
        query_text: str,
        cia: Dict[str, bool],
    ) -> List[ComplianceControl]:
        """
        4-stage exhaustive compliance audit sweep.
        Returns ALL applicable controls, not just top-K.
        """
        client = self._get_client()
        seen_ids: set = set()
        all_controls: List[ComplianceControl] = []

        # ── Stage 1: Exact technique_id filter (deterministic) ────────────────
        if technique_id:
            try:
                exact_results, _ = await client.scroll(
                    collection_name=COLL_COMPLIANCE,
                    scroll_filter=Filter(must=[
                        FieldCondition(
                            key="mitre_technique_ids",
                            match=MatchAny(any=[technique_id])
                        )
                    ]),
                    limit=200,   # fetch all — compliance needs exhaustive recall
                    with_payload=True,
                    with_vectors=False,
                )
                for pt in exact_results:
                    ctrl = self._parse_compliance_payload(pt.payload, "exact")
                    uid = f"{ctrl.framework}::{ctrl.control_id}"
                    if uid not in seen_ids:
                        seen_ids.add(uid)
                        all_controls.append(ctrl)
                logger.info(f"Compliance Stage 1 (exact): {len(all_controls)} controls")
            except Exception as e:
                logger.warning(f"Compliance Stage 1 failed: {e}")

        # ── Stage 2: Per-framework semantic sweep ─────────────────────────────
        if query_text:
            query_emb = _embed(query_text)
            frameworks = [
                "NIST_CSF", "CIS_18", "ISO_27001", "ISO_42001",
                "GDPR", "HIPAA", "PCI_DSS", "SOC2",
                "SEBI_CSCRF", "DPDP", "NIST_800_53",
            ]
            # Build CIA-weighted query suffix
            cia_suffix = ""
            if cia.get("confidentiality"):
                cia_suffix += " confidentiality data protection access control"
            if cia.get("integrity"):
                cia_suffix += " integrity data modification audit logging"
            if cia.get("availability"):
                cia_suffix += " availability disruption resilience business continuity"

            sem_tasks = [
                self._sweep_framework(
                    client, fw, query_emb, COMPLIANCE_PER_FRAMEWORK_LIMIT
                )
                for fw in frameworks
            ]
            sweep_results = await asyncio.gather(*sem_tasks, return_exceptions=True)

            added_semantic = 0
            for fw_pts in sweep_results:
                if isinstance(fw_pts, Exception):
                    continue
                for pt in fw_pts:
                    ctrl = self._parse_compliance_payload(pt.payload, "semantic")
                    uid = f"{ctrl.framework}::{ctrl.control_id}"
                    if uid not in seen_ids:
                        seen_ids.add(uid)
                        all_controls.append(ctrl)
                        added_semantic += 1
            logger.info(f"Compliance Stage 2 (semantic): +{added_semantic} unique controls")

        logger.info(f"Compliance total: {len(all_controls)} controls across frameworks")
        return all_controls

    async def _sweep_framework(
        self,
        client: AsyncQdrantClient,
        framework: str,
        query_emb: np.ndarray,
        limit: int,
    ) -> List[Any]:
        """Semantic search scoped to a single framework."""
        try:
            results = await client.query_points(
                collection_name=COLL_COMPLIANCE,
                query=query_emb.tolist(),
                query_filter=Filter(must=[
                    FieldCondition(key="framework", match=MatchValue(value=framework))
                ]),
                limit=limit,
                with_payload=True,
                with_vectors=False,
            )
            return results.points
        except Exception as e:
            logger.debug(f"Compliance sweep [{framework}] failed: {e}")
            return []

    def _parse_compliance_payload(self, payload: Dict, match_type: str) -> ComplianceControl:
        return ComplianceControl(
            framework=payload.get("framework", ""),
            control_id=payload.get("control_id", ""),
            control_name=payload.get("control_name", ""),
            description=payload.get("description", ""),
            parent_chain=payload.get("parent_chain", []),
            mitre_technique_ids=payload.get("mitre_technique_ids", []),
            cia_flags=payload.get("cia_flags", {}),
            severity_weight=payload.get("severity_weight", 0.5),
            match_type=match_type,
        )

    # ── Query Builder ──────────────────────────────────────────────────────────

    def _build_query(
        self,
        technique_id: Optional[str],
        technique_name: str,
        tactic_name: str,
        asset_type: str,
        severity: str,
        cia: Dict[str, bool],
    ) -> str:
        parts = []
        if technique_id:
            parts.append(technique_id)
        if technique_name:
            parts.append(technique_name)
        if tactic_name:
            parts.append(tactic_name)
        if asset_type:
            parts.append(f"asset: {asset_type}")
        if severity:
            parts.append(f"severity: {severity}")
        cia_labels = [k for k, v in cia.items() if v]
        if cia_labels:
            parts.append(f"CIA: {', '.join(cia_labels)}")
        return " | ".join(parts) if parts else "security alert"

    async def index_incident(self, incident: Dict[str, Any]) -> bool:
        """
        Auto-ingest hook. Called from alert_pipeline.py when an analyst closes an alert.
        Embeds the incident summary and upserts into historical_incidents collection.
        """
        from qdrant_client.models import PointStruct
        import uuid
        client = self._get_client()
        try:
            text = (
                f"{incident.get('summary', '')} "
                f"Technique: {incident.get('mitre_technique', '')}. "
                f"Resolution: {incident.get('resolution', '')}"
            )
            emb = _embed(text)
            point = PointStruct(
                id=str(uuid.uuid4()),
                vector=emb.tolist(),
                payload={
                    "incident_id":     incident.get("incident_id", str(uuid.uuid4())),
                    "summary":         incident.get("summary", ""),
                    "mitre_technique": incident.get("mitre_technique", ""),
                    "resolution":      incident.get("resolution", ""),
                    "outcome":         incident.get("outcome", "resolved"),
                    "analyst_approved": incident.get("analyst_approved", True),
                    "timestamp":       incident.get("timestamp"),
                }
            )
            await client.upsert(collection_name=COLL_INCIDENTS, points=[point])
            logger.info(f"Indexed incident: {point.payload['incident_id']}")
            return True
        except Exception as e:
            logger.error(f"Failed to index incident: {e}")
            return False


# ── Global singleton ───────────────────────────────────────────────────────────
kb_service = KBRetrievalService()
