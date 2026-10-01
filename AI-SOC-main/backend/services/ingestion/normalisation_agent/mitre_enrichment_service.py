"""
3-Layer MITRE ATT&CK Enrichment Service
=========================================

Layer 1: Direct ID extraction from SIEM metadata
Layer 2: Semantic sub-technique inference (when parent technique is known)
Layer 3: Full semantic mapping (no MITRE ID present at all)

All semantic search uses sentence-transformers embeddings stored in Qdrant.
Covers all 216 techniques + 475 sub-techniques (691 total).

Replaces both the old MITREPredictor (rule-based) and the standalone
mitre-mapper Docker service. This is now the single source of truth for
all MITRE ATT&CK enrichment in the SOAR platform.
"""

import os
import re
import json
import pickle
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
# COLLECTION_NAME = "mitre_techniques"
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION_MITRE", "mitre_techniques")
EMBEDDING_MODEL = "BAAI/bge-large-en-v1.5"  # 1024-dim, strong retrieval quality
# BGE asymmetric retrieval: queries get this prefix at search time;
# passages got BGE_PASSAGE_PREFIX at index time (see index_mitre_to_qdrant.py)
BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "
# Data files live alongside the enrichment service, not under ml/
LOOKUP_PATH = Path(__file__).parent / "mitre_data" / "mitre_id_lookup.pkl"

QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))

# Confidence thresholds
HIGH_CONFIDENCE = 0.85
MEDIUM_CONFIDENCE = 0.70

# MITRE ID pattern
MITRE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Fields to search for MITRE IDs in Layer 1
LAYER1_FIELDS = [
    ("rule", "mitre", "id"),
    ("rule", "mitre", "technique"),
    ("finding", "types"),
    ("unmapped", "mitre_technique"),
    ("unmapped", "mitre_id"),
    ("metadata", "mitre_technique_id"),
    ("metadata", "attack_technique"),
    ("enrichments", "mitre", "technique_id"),
]


# ── Singleton helpers ────────────────────────────────────────────────────────

_embedding_model = None
_qdrant_client = None
_cross_encoder = None
_id_lookup: Optional[Dict[str, Any]] = None


def _get_cross_encoder():
    global _cross_encoder
    if _cross_encoder is None:
        from sentence_transformers import CrossEncoder

        logger.info("Loading CrossEncoder: cross-encoder/ms-marco-MiniLM-L-6-v2")
        _cross_encoder = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
    return _cross_encoder


def _get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        from sentence_transformers import SentenceTransformer

        logger.info(f"Loading embedding model: {EMBEDDING_MODEL}")
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL)
    return _embedding_model


def _get_qdrant_client():
    global _qdrant_client
    if _qdrant_client is None:
        from qdrant_client import QdrantClient

        _qdrant_client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    return _qdrant_client


def _get_id_lookup() -> Dict[str, Any]:
    global _id_lookup
    if _id_lookup is None:
        if LOOKUP_PATH.exists():
            with open(LOOKUP_PATH, "rb") as f:
                _id_lookup = pickle.load(f)
            logger.info(f"Loaded MITRE ID lookup ({len(_id_lookup)} entries)")
        else:
            logger.warning(
                f"MITRE ID lookup not found at {LOOKUP_PATH}. "
                "Run scripts/setup/index_mitre_to_qdrant.py first."
            )
            _id_lookup = {}
    return _id_lookup


def _qdrant_vector_search(
    client: Any,
    *,
    collection_name: str,
    query_vector: List[float],
    query_filter: Any,
    limit: int,
    with_payload: bool = True,
) -> List[Any]:
    """
    Vector search compatible with qdrant-client versions that have `query_points`
    (newer) or only `search` (older). Returns scored points (.score, .payload).
    """
    if hasattr(client, "query_points"):
        resp = client.query_points(
            collection_name=collection_name,
            query=query_vector,
            query_filter=query_filter,
            limit=limit,
            with_payload=with_payload,
        )
        pts = getattr(resp, "points", None)
        return list(pts or [])
    hits = client.search(
        collection_name=collection_name,
        query_vector=query_vector,
        query_filter=query_filter,
        limit=limit,
        with_payload=with_payload,
    )
    return list(hits or [])


# ── Core Service ─────────────────────────────────────────────────────────────


class MITREEnrichmentService:
    """
    3-Layer MITRE ATT&CK enrichment pipeline.

    Usage:
        service = MITREEnrichmentService()
        result = service.enrich(alert)
        # result is stored in alert['enrichments']['mitre']
    """

    def __init__(self):
        self._model = None  # lazy-loaded
        self._client = None  # lazy-loaded
        self._lookup = None  # lazy-loaded

    @property
    def model(self):
        if self._model is None:
            self._model = _get_embedding_model()
        return self._model

    @property
    def client(self):
        if self._client is None:
            self._client = _get_qdrant_client()
        return self._client

    @property
    def lookup(self):
        if self._lookup is None:
            self._lookup = _get_id_lookup()
        return self._lookup

    # ── Public API ───────────────────────────────────────────────────────────

    def enrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronous enrichment (legacy compatibility).
        """
        if "enrichments" not in alert:
            alert["enrichments"] = {}

        try:
            alert_text = self._build_alert_text(alert)
            result = self._run_pipeline(alert, alert_text)
        except Exception as e:
            logger.error(f"MITRE enrichment failed: {e}", exc_info=True)
            result = self._empty_result("error", str(e))

        alert["enrichments"]["mitre"] = result
        return alert

    async def aenrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Async enrichment with LLM Denoising.
        """
        if "enrichments" not in alert:
            alert["enrichments"] = {}

        try:
            alert_text = await self._denoise_alert(alert)

            # ADD THESE TWO LINES
            logger.info(f"[MITRE-DEBUG] Alert keys: {list(alert.keys())}")
            logger.info(f"[MITRE-DEBUG] Alert text fed to embedder: {alert_text[:500]}")
            result = self._run_pipeline(alert, alert_text)
        except Exception as e:
            logger.error(f"MITRE async enrichment failed: {e}", exc_info=True)
            result = self._empty_result("error", str(e))

        alert["enrichments"]["mitre"] = result
        return alert

    async def _denoise_alert(self, alert: Dict[str, Any]) -> str:
        try:
            from backend.services.agentic.config.llm_service import llm_service

            raw_text = self._build_alert_text(alert)
            prompt = (
                f"You are an elite Cyber Threat Intelligence (CTI) enrichment analyst. Your sole purpose is to "
                f"extract highly accurate, tactically relevant telemetry from raw SIEM alerts for MITRE ATT&CK mapping.\n"
                f"Identify and retain ONLY the attack action (e.g., Block/Drop/Allow), protocol (TCP/UDP), "
                f"destination port, firewall policy/rule, traffic direction, and explicit threat classifications.\n"
                f"CRITICAL: Strip out all specific IP addresses, MAC addresses, timestamps, and conversational prefixes. "
                f"Do not write 'Here is the rewritten alert' or any filler. Output EXACTLY one dense, highly accurate sentence.\n\n"
                f"RAW ALERT: {raw_text}"
            )

            response = await llm_service.ainvoke(
                prompt=prompt,
                tier="secondary",
                system_message=(
                    "You are a CTI Analyst. Output a single, highly accurate sentence summarizing the tactical mechanics of the network/system event without dynamic values like IPs or GUIDs."
                ),
            )
            clean_text = response.content.strip()
            if len(clean_text) > 20:
                return BGE_QUERY_PREFIX + clean_text
        except Exception as e:
            logger.warning(f"LLM Denoising failed, using raw text: {e}")

        return self._build_alert_text(alert)

    def _get_platform_filter(self, alert: Dict[str, Any]):
        """Generate a Qdrant FieldCondition based on SIEM source."""
        from qdrant_client.models import FieldCondition, MatchAny

        decoder = str(alert.get("decoder", {}).get("name", "")).lower()
        agent_name = str(alert.get("agent", {}).get("name", "")).lower()
        rule_desc = str(alert.get("rule", {}).get("description", "")).lower()

        platforms = set()

        if "aws" in decoder or "cloudtrail" in decoder or "guardduty" in decoder:
            platforms.update(["AWS", "IaaS", "SaaS"])
        if "gcp" in decoder or "azure" in decoder or "o365" in decoder:
            platforms.update(["IaaS", "SaaS", "Azure", "GCP"])

        if "windows" in agent_name or "windows" in rule_desc:
            platforms.add("Windows")
        elif "linux" in agent_name or "syscheck" in decoder or "auditd" in decoder:
            platforms.add("Linux")
        elif "macos" in agent_name:
            platforms.add("macOS")

        if (
            "firewall" in rule_desc
            or "barracuda" in decoder
            or "cisco" in decoder
            or "paloalto" in decoder
        ):
            platforms.add("Network")

        if platforms:
            return FieldCondition(key="platforms", match=MatchAny(any=list(platforms)))
        return None

    # ── Layer Orchestration ──────────────────────────────────────────────────

    def _run_pipeline(self, alert: Dict[str, Any], alert_text: str) -> Dict[str, Any]:
        """Run the 3-layer pipeline and return the enrichment result."""

        # ── Layer 1: Direct ID extraction ────────────────────────────────────
        tech_id, sub_id = self._layer1_extract_ids(alert)

        if tech_id and sub_id:
            # Both technique and sub-technique found directly
            return self._build_result(tech_id, sub_id, "layer1", 1.0, 1.0)

        if tech_id:
            # Technique found, try to infer sub-technique semantically
            logger.debug(
                f"Layer 1: found technique {tech_id}, running Layer 2 for sub-technique"
            )
            sub_id, sub_conf = self._layer2_infer_subtechnique(
                alert, tech_id, alert_text
            )
            return self._build_result(
                tech_id, sub_id, "layer1+layer2_semantic", 1.0, sub_conf
            )

        # ── Layer 3: Full semantic mapping ───────────────────────────────────
        logger.debug("Layer 3: no MITRE ID found, running full semantic search")
        tech_id, tech_conf, sub_id, sub_conf = self._layer3_full_semantic(
            alert, alert_text
        )
        # Always return best guess — analyst_review_required=True is set in
        # _build_result when tech_conf < MEDIUM_CONFIDENCE, allowing analysts
        # to label and improve mappings over time.
        return self._build_result(
            tech_id, sub_id, "layer3_semantic", tech_conf, sub_conf
        )

    # ── Layer 1 ──────────────────────────────────────────────────────────────

    def _layer1_extract_ids(self, alert: Dict) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract MITRE technique/sub-technique IDs from alert metadata.
        Returns (technique_id, subtechnique_id) — either may be None.
        """
        found_ids = set()

        # Walk known field paths
        for path in LAYER1_FIELDS:
            value = self._get_nested(alert, path)
            if value is None:
                continue
            if isinstance(value, list):
                for v in value:
                    ids = MITRE_ID_PATTERN.findall(str(v))
                    found_ids.update(ids)
            else:
                ids = MITRE_ID_PATTERN.findall(str(value))
                found_ids.update(ids)

        # Also scan the entire alert as JSON string (catches any field)
        alert_str = json.dumps(alert, default=str)
        found_ids.update(MITRE_ID_PATTERN.findall(alert_str))

        if not found_ids:
            return None, None

        # Separate techniques and sub-techniques
        techniques = sorted([i for i in found_ids if "." not in i])
        subtechniques = sorted([i for i in found_ids if "." in i])

        tech_id = (
            techniques[0]
            if techniques
            else (subtechniques[0].split(".")[0] if subtechniques else None)
        )
        sub_id = subtechniques[0] if subtechniques else None

        if tech_id:
            logger.debug(f"Layer 1: extracted technique={tech_id}, sub={sub_id}")

        return tech_id, sub_id

    # ── Layer 2 ──────────────────────────────────────────────────────────────

    def _layer2_infer_subtechnique(
        self, alert: Dict, parent_id: str, alert_text: str = None
    ) -> Tuple[Optional[str], float]:
        """
        Semantic search within the sub-techniques of a known parent technique.
        Returns (subtechnique_id, confidence).
        """
        try:
            from qdrant_client.models import Filter, FieldCondition, MatchValue

            if not alert_text:
                alert_text = self._build_alert_text(alert)
            embedding = self.model.encode(
                alert_text, normalize_embeddings=True
            ).tolist()

            must_conditions = [
                FieldCondition(key="is_subtechnique", match=MatchValue(value=True)),
                FieldCondition(key="parent_id", match=MatchValue(value=parent_id)),
            ]
            plat_filter = self._get_platform_filter(alert)
            if plat_filter:
                must_conditions.append(plat_filter)

            # Filter to only sub-techniques of this parent
            results = _qdrant_vector_search(
                self.client,
                collection_name=COLLECTION_NAME,
                query_vector=embedding,
                query_filter=Filter(must=must_conditions),
                limit=1,
                with_payload=True,
            )

            if results and results[0].score >= MEDIUM_CONFIDENCE:
                sub_id = results[0].payload["id"]
                confidence = round(results[0].score, 3)
                logger.debug(
                    f"Layer 2: inferred sub-technique {sub_id} (score={confidence})"
                )
                return sub_id, confidence

        except Exception as e:
            logger.warning(f"Layer 2 semantic search failed: {e}")

        return None, 0.0

    # ── Layer 3 ──────────────────────────────────────────────────────────────

    def _layer3_full_semantic(
        self, alert: Dict, alert_text: str = None
    ) -> Tuple[Optional[str], float, Optional[str], float]:
        """
        Full semantic search across all 691 MITRE entries, with Cross-Encoder rescoring.
        Returns (technique_id, tech_confidence, subtechnique_id, sub_confidence).
        """
        try:
            from qdrant_client.models import Filter, FieldCondition, MatchValue

            if not alert_text:
                alert_text = self._build_alert_text(alert)
            embedding = self.model.encode(
                alert_text, normalize_embeddings=True
            ).tolist()

            must_conditions = [
                FieldCondition(key="is_subtechnique", match=MatchValue(value=False))
            ]
            plat_filter = self._get_platform_filter(alert)
            if plat_filter:
                must_conditions.append(plat_filter)

            # Search techniques first (not sub-techniques)
            tech_results = _qdrant_vector_search(
                self.client,
                collection_name=COLLECTION_NAME,
                query_vector=embedding,
                query_filter=Filter(must=must_conditions),
                limit=10,  # Expand initial retrieval for re-ranking
                with_payload=True,
            )

            if not tech_results:
                return None, 0.0, None, 0.0

            # ── Cross-Encoder Re-Ranking ──
            if len(tech_results) > 1:
                try:
                    ce = _get_cross_encoder()
                    pairs = [
                        [
                            alert_text,
                            t.payload.get("description", t.payload.get("name", "")),
                        ]
                        for t in tech_results
                    ]
                    scores = ce.predict(pairs)
                    # Sort results by cross-encoder score descending
                    scored_results = sorted(
                        zip(tech_results, scores), key=lambda x: x[1], reverse=True
                    )
                    best_tech = scored_results[0][0]
                except Exception as ce_err:
                    logger.warning(f"Cross-encoder re-ranking failed: {ce_err}")
                    best_tech = tech_results[0]
            else:
                best_tech = tech_results[0]

            tech_id = best_tech.payload["id"]
            tech_conf = round(best_tech.score, 3)

            if tech_conf < 0.65:
                logger.debug(
                    f"Layer 3: no technique found above 0.65 threshold (best={tech_id} @ {tech_conf})"
                )
                return None, 0.0, None, 0.0

            logger.debug(f"Layer 3: best technique {tech_id} (score={tech_conf})")

            # Now search for best sub-technique within this parent
            sub_id, sub_conf = self._layer2_infer_subtechnique(
                alert, tech_id, alert_text
            )

            return tech_id, tech_conf, sub_id, sub_conf

        except Exception as e:
            logger.warning(f"Layer 3 semantic search failed: {e}")
            return None, 0.0, None, 0.0

    # ── Result Builder ───────────────────────────────────────────────────────

    def _build_result(
        self,
        tech_id: Optional[str],
        sub_id: Optional[str],
        method: str,
        tech_conf: float,
        sub_conf: float,
    ) -> Dict[str, Any]:
        """Build the final enrichment result dict."""
        lookup = self.lookup

        # Technique info
        tech_entry = lookup.get(tech_id, {}) if tech_id else {}
        raw_tactics = tech_entry.get("tactics", [])

        # Enrich every tactic entry with its TA-ID
        enriched_tactics = [
            {
                **t,
                "tactic_id": self._get_tactic_id(t.get("shortname")),
            }
            for t in raw_tactics
        ]
        primary_tactic = enriched_tactics[0] if enriched_tactics else {}

        # Sub-technique info
        sub_entry = lookup.get(sub_id, {}) if sub_id else {}

        # Determine if analyst review is needed
        analyst_review = tech_conf < MEDIUM_CONFIDENCE

        result = {
            # Primary tactic
            "tactic_id": primary_tactic.get("tactic_id"),
            "tactic_name": primary_tactic.get("name", "Unknown"),
            "tactic_shortname": primary_tactic.get("shortname", "unknown"),
            # Technique
            "technique_id": tech_id,
            "technique_name": tech_entry.get("name", tech_id),
            "technique_confidence": tech_conf,
            # Sub-technique
            "subtechnique_id": sub_id,
            "subtechnique_name": sub_entry.get("name") if sub_id else None,
            "subtechnique_confidence": sub_conf if sub_id else None,
            # All tactics — each entry has {name, shortname, tactic_id}
            "all_tactics": enriched_tactics,
            # Metadata
            "mapping_method": method,
            "analyst_review_required": analyst_review,
            "platforms": tech_entry.get("platforms", []),
            "data_sources": tech_entry.get("data_sources", []),
        }

        logger.info(
            f"MITRE enrichment: {tech_id} ({tech_entry.get('name', '?')}) "
            f"→ tactic={primary_tactic.get('tactic_id')} ({primary_tactic.get('name', '?')}) "
            f"→ sub={sub_id} via {method} [conf={tech_conf:.2f}]"
        )
        return result

    def _empty_result(self, reason: str, detail: str = "") -> Dict[str, Any]:
        return {
            "tactic_id": None,
            "tactic_name": "Unknown",
            "tactic_shortname": "unknown",
            "technique_id": None,
            "technique_name": None,
            "technique_confidence": 0.0,
            "subtechnique_id": None,
            "subtechnique_name": None,
            "subtechnique_confidence": None,
            "all_tactics": [],
            "mapping_method": f"failed_{reason}",
            "analyst_review_required": True,
            "platforms": [],
            "data_sources": [],
            "error": detail,
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _build_alert_text(self, alert: Dict) -> str:
        """Build rich text representation of alert for embedding."""
        parts = []

        # Finding title + description
        finding = alert.get("finding", {})
        if finding.get("title"):
            parts.append(f"Alert: {finding['title']}")
        if finding.get("desc"):
            parts.append(f"Description: {finding['desc'][:400]}")

        # Rule description (Wazuh-style)
        rule = alert.get("rule", {})
        if rule.get("description"):
            parts.append(f"Rule: {rule['description']}")

        # Process info
        process = alert.get("process", {})
        if process.get("name"):
            parts.append(f"Process: {process['name']}")
        if process.get("cmd_line"):
            parts.append(f"Command: {process['cmd_line'][:200]}")

        # File info
        file_info = alert.get("file", {})
        if file_info.get("path"):
            parts.append(f"File: {file_info['path']}")

        # Network info
        network = alert.get("network_activity", {})
        if network.get("protocol"):
            parts.append(f"Protocol: {network['protocol']}")

        # Action
        if alert.get("action"):
            parts.append(f"Action: {alert['action']}")

        # Raw data fallback
        if not parts and alert.get("raw_data"):
            parts.append(str(alert["raw_data"])[:500])

        # Message field (generic)
        if alert.get("message"):
            parts.append(f"Message: {alert['message'][:300]}")

        return BGE_QUERY_PREFIX + (
            " | ".join(parts) if parts else "Unknown security alert"
        )

    def _get_nested(self, d: Dict, path: tuple) -> Any:
        """Safely get nested dict value."""
        for key in path:
            if not isinstance(d, dict):
                return None
            d = d.get(key)
        return d

    def _get_tactic_id(self, tactic_shortname):
        """Map tactic shortname to its official MITRE TA-XXXX ID.

        Primary source: the lookup pickle built by index_mitre_to_qdrant.py,
        which embeds tactic_id directly from the MITRE STIX data.
        This guarantees correctness regardless of ATT&CK version.

        Fallback: inline dict for old pickles lacking tactic_id field.
        Remove once the index is regenerated.
        """
        if not tactic_shortname:
            return None

        normalised = tactic_shortname.lower().replace("_", "-").replace(" ", "-")

        # Primary: build a shortname->TA-ID cache from the lookup pickle (lazy, once)
        if not hasattr(self, "_tactic_id_cache"):
            self._tactic_id_cache = {}
            for entry in self.lookup.values():
                for t in entry.get("tactics", []):
                    sn = t.get("shortname", "")
                    tid = t.get("tactic_id")  # None for old pickles
                    if sn and sn not in self._tactic_id_cache:
                        self._tactic_id_cache[sn] = tid

        tactic_id = self._tactic_id_cache.get(normalised)
        if tactic_id is not None:
            return tactic_id  # from STIX -- fully guaranteed

        # Fallback: static dict for old pickles missing tactic_id field
        _FALLBACK = {
            "reconnaissance": "TA0043",
            "resource-development": "TA0042",
            "initial-access": "TA0001",
            "execution": "TA0002",
            "persistence": "TA0003",
            "privilege-escalation": "TA0004",
            "defense-evasion": "TA0005",
            "credential-access": "TA0006",
            "discovery": "TA0007",
            "lateral-movement": "TA0008",
            "collection": "TA0009",
            "command-and-control": "TA0011",
            "exfiltration": "TA0010",
            "impact": "TA0040",
        }
        tactic_id = _FALLBACK.get(normalised)
        if tactic_id is None:
            import logging

            logging.getLogger(__name__).warning(
                f"Unknown tactic shortname '{tactic_shortname}' not in lookup or "
                "fallback dict. Regenerate the MITRE index if this is a new ATT&CK tactic."
            )
        return tactic_id


_service: Optional[MITREEnrichmentService] = None


def get_mitre_enrichment_service() -> MITREEnrichmentService:
    """Get singleton MITREEnrichmentService."""
    global _service
    if _service is None:
        _service = MITREEnrichmentService()
    return _service


def get_mitre_enrichment(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function — enriches alert and returns the mitre enrichment dict.
    Compatible with the existing alert_pipeline.py call signature.
    """
    service = get_mitre_enrichment_service()
    service.enrich(alert)
    return alert.get("enrichments", {}).get("mitre", {})
