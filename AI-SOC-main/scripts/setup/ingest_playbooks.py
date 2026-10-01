"""
Playbook Ingest Script
=======================
Ingests playbooks into Qdrant `playbooks` collection from 3 sources:
  1. SVG playbooks parsed from Playbooks/ directory
  2. STIX ATT&CK mitigations (from mitre_stix_cache.json)
  3. D3FEND countermeasures (from mitre_attack_defend collection or D3FEND API)

Chunking strategy (2-level):
  Level 1 — summary chunk: trigger + all steps as a block (for retrieval)
  Level 2 — step chunks: individual steps (for detailed execution context)

Run:
    python scripts/setup/ingest_playbooks.py
"""

import json
import logging
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, FieldCondition, Filter, MatchValue,
    PointStruct, VectorParams,
)
from sentence_transformers import SentenceTransformer

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent.parent
STIX_CACHE = ROOT / "backend" / "services" / "enrichment" / "mitre_data" / "mitre_stix_cache.json"
SVG_PLAYBOOKS = ROOT / "Playbooks" / "Playbooks"
KB_DATA_DIR   = ROOT / "backend" / "services" / "knowledge_base" / "data"
KB_DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── Config ─────────────────────────────────────────────────────────────────────
QDRANT_HOST     = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT     = int(os.getenv("QDRANT_PORT", "6333"))
COLLECTION_NAME = "playbooks"
EMBEDDING_MODEL = "BAAI/bge-large-en-v1.5"
BGE_PASSAGE_PREFIX = "Represent this sentence for searching relevant passages: "
VECTOR_SIZE     = 1024
BATCH_SIZE      = 32

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def load_embedder() -> SentenceTransformer:
    logger.info(f"Loading {EMBEDDING_MODEL}...")
    model = SentenceTransformer(EMBEDDING_MODEL)
    logger.info("Model loaded.")
    return model


def embed_texts(model: SentenceTransformer, texts: List[str]) -> np.ndarray:
    prefixed = [BGE_PASSAGE_PREFIX + t for t in texts]
    return model.encode(prefixed, batch_size=BATCH_SIZE, show_progress_bar=True,
                        normalize_embeddings=True)


def setup_collection(client: QdrantClient):
    try:
        client.get_collection(COLLECTION_NAME)
        logger.info(f"Collection '{COLLECTION_NAME}' already exists.")
        return
    except Exception:
        pass
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
    )
    logger.info(f"Created collection '{COLLECTION_NAME}'.")


# ── Source 1: SVG Playbooks ────────────────────────────────────────────────────

def load_svg_playbooks() -> List[Dict]:
    """Run SVG parser inline to get structured playbooks."""
    sys.path.insert(0, str(ROOT / "scripts" / "setup"))
    from parse_svg_playbooks import parse_all_svg_playbooks
    return parse_all_svg_playbooks(SVG_PLAYBOOKS)


# ── Source 2: STIX ATT&CK Mitigations → Playbooks ─────────────────────────────

def load_stix_playbooks() -> List[Dict]:
    """
    Build one playbook per ATT&CK technique from STIX mitigations.
    Each mitigation object in STIX has: id, name, description, relationship to technique.
    """
    if not STIX_CACHE.exists():
        logger.warning(f"STIX cache not found at {STIX_CACHE}. Skipping STIX playbooks.")
        return []

    logger.info("Loading STIX cache...")
    with open(STIX_CACHE, encoding="utf-8") as f:
        stix_data = json.load(f)

    objects = stix_data.get("objects", [])

    # Index techniques and mitigations
    techniques = {}
    mitigations = {}
    relationships = []

    for obj in objects:
        otype = obj.get("type", "")
        if otype == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            tech_id = next((r["external_id"] for r in ext_refs
                            if r.get("source_name") == "mitre-attack"), None)
            if tech_id:
                tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                           if p.get("kill_chain_name") == "mitre-attack"]
                techniques[obj["id"]] = {
                    "id": tech_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "")[:400],
                    "tactic": tactics[0] if tactics else "unknown",
                    "detection": obj.get("x_mitre_detection", "")[:400],
                }
        elif otype == "course-of-action":
            mitigations[obj["id"]] = {
                "name": obj.get("name", ""),
                "description": obj.get("description", "")[:500],
            }
        elif otype == "relationship" and obj.get("relationship_type") == "mitigates":
            relationships.append({
                "mitigation_id": obj.get("source_ref", ""),
                "technique_id":  obj.get("target_ref", ""),
            })

    logger.info(f"STIX: {len(techniques)} techniques, {len(mitigations)} mitigations, "
                f"{len(relationships)} mitigation→technique relationships")

    # Group mitigations by technique
    tech_mitigations: Dict[str, List[Dict]] = {}
    for rel in relationships:
        mit_obj = mitigations.get(rel["mitigation_id"])
        tech_obj = techniques.get(rel["technique_id"])
        if not mit_obj or not tech_obj:
            continue
        tid = tech_obj["id"]
        tech_mitigations.setdefault(tid, [])
        tech_mitigations[tid].append(mit_obj)

    # Build playbooks
    playbooks = []
    for stix_id, tech in techniques.items():
        tid = tech["id"]
        mits = tech_mitigations.get(tid, [])
        if not mits:
            continue  # Skip techniques with no official mitigations

        steps = []
        for i, mit in enumerate(mits, 1):
            steps.append(f"{i}. [{mit['name']}] {mit['description']}")

        # Add detection guidance as final step
        if tech.get("detection"):
            steps.append(f"{len(steps)+1}. [Detection] {tech['detection']}")

        playbooks.append({
            "playbook_id":         f"PB_STIX_{tid.replace('.', '_')}",
            "title":               f"{tech['name']} — Response Playbook",
            "trigger":             f"MITRE ATT&CK {tid} ({tech['name']}) detected",
            "steps":               steps,
            "mitre_technique_ids": [tid],
            "tactic":              tech["tactic"].replace("-", " ").title(),
            "d3fend_categories":   [],   # enriched later by mitre_attack_defend
            "source":              "stix_mitigations",
            "chunk_type":          "summary",
            "description":         tech.get("description", ""),
        })

    logger.info(f"Built {len(playbooks)} STIX-based playbooks.")
    return playbooks


# ── Chunk + Embed + Upsert ─────────────────────────────────────────────────────

def playbook_to_chunks(pb: Dict) -> List[Dict]:
    """Create 2-level chunks: 1 summary chunk + 1 chunk per step."""
    chunks = []

    # Level 1: Summary chunk (for retrieval)
    summary_text = (
        f"Playbook: {pb['title']}. "
        f"Trigger: {pb['trigger']}. "
        f"Tactic: {pb.get('tactic', '')}. "
        f"Techniques: {', '.join(pb.get('mitre_technique_ids', []))}. "
        f"Steps overview: {' | '.join(pb['steps'][:5])}"
    )
    chunks.append({
        **pb,
        "chunk_type":  "summary",
        "chunk_text":  summary_text,
        "chunk_index": 0,
        "step_number": None,
    })

    # Level 2: Individual step chunks (for execution detail)
    for i, step in enumerate(pb["steps"], 1):
        step_text = (
            f"Playbook: {pb['title']}. "
            f"Trigger: {pb['trigger']}. "
            f"Step {i}: {step}"
        )
        chunks.append({
            **pb,
            "chunk_type":  "step",
            "chunk_text":  step_text,
            "chunk_index": i,
            "step_number": i,
            "steps":       [step],  # only this step in the chunk
        })

    return chunks


def ingest_playbooks(client: QdrantClient, model: SentenceTransformer, playbooks: List[Dict]):
    logger.info(f"Ingesting {len(playbooks)} playbooks → '{COLLECTION_NAME}'...")

    # Expand to chunks
    all_chunks = []
    for pb in playbooks:
        all_chunks.extend(playbook_to_chunks(pb))

    logger.info(f"Total chunks (summary + steps): {len(all_chunks)}")

    # Embed all chunks
    texts = [c["chunk_text"] for c in all_chunks]
    embeddings = embed_texts(model, texts)

    # Build Qdrant points
    points = []
    existing_ids = set()
    for chunk, emb in zip(all_chunks, embeddings):
        pid = str(uuid.uuid5(uuid.NAMESPACE_DNS, chunk["playbook_id"] + str(chunk["chunk_index"])))
        if pid in existing_ids:
            continue
        existing_ids.add(pid)

        payload = {k: v for k, v in chunk.items() if k != "chunk_text"}
        payload["chunk_text"] = chunk["chunk_text"][:1000]  # store first 1000 chars

        points.append(PointStruct(id=pid, vector=emb.tolist(), payload=payload))

    # Batch upsert
    for i in range(0, len(points), BATCH_SIZE):
        batch = points[i:i + BATCH_SIZE]
        client.upsert(collection_name=COLLECTION_NAME, points=batch)
        logger.info(f"  Upserted {min(i + BATCH_SIZE, len(points))}/{len(points)} chunks")

    logger.info(f"✅ Playbook ingestion complete: {len(points)} chunks in Qdrant")


def main():
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    setup_collection(client)
    model = load_embedder()

    # Load from all sources
    svg_playbooks  = load_svg_playbooks()
    stix_playbooks = load_stix_playbooks()

    # Deduplicate by playbook_id
    all_playbooks: Dict[str, Dict] = {}
    for pb in svg_playbooks + stix_playbooks:
        pid = pb["playbook_id"]
        if pid not in all_playbooks:
            all_playbooks[pid] = pb

    playbooks = list(all_playbooks.values())
    logger.info(f"Total unique playbooks to ingest: {len(playbooks)} "
                f"(SVG: {len(svg_playbooks)}, STIX: {len(stix_playbooks)})")

    ingest_playbooks(client, model, playbooks)


if __name__ == "__main__":
    main()
