"""
MITRE ATT&CK → Qdrant Indexer
==============================
One-time setup script. Downloads all MITRE ATT&CK Enterprise techniques
and sub-techniques (691 total), generates semantic embeddings using
sentence-transformers, and loads them into Qdrant.

Run once before starting the enrichment engine:
    python scripts/setup/index_mitre_to_qdrant.py

Collection: mitre_techniques
Vector size: 1024 (BAAI/bge-large-en-v1.5)
"""

import sys
import os
import json
import logging
import requests
import pickle
from pathlib import Path
from typing import List, Dict, Any

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ── Config ──────────────────────────────────────────────────────────────────
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CACHE_PATH = Path(__file__).parent.parent.parent / "backend" / "services" / "enrichment" / "mitre_data" / "mitre_stix_cache.json"
COLLECTION_NAME = "mitre_techniques"
EMBEDDING_MODEL = "BAAI/bge-large-en-v1.5"
VECTOR_SIZE = 1024        # bge-large-en-v1.5 output dimension
BATCH_SIZE = 32           # smaller batch — larger model

# BGE corpus instruction prefix (improves retrieval quality on bge-large-v1.5)
BGE_PASSAGE_PREFIX = "Represent this sentence for searching relevant passages: "

QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))

# Embedding cache path (in mitre_data alongside the lookup)
EMBEDDING_CACHE_PATH = Path(__file__).parent.parent.parent / "backend" / "services" / "enrichment" / "mitre_data" / "mitre_embeddings_bge.npy"


# ── MITRE Data Download ──────────────────────────────────────────────────────

def download_mitre_stix() -> Dict:
    """Download MITRE ATT&CK STIX data (with local cache)."""
    if CACHE_PATH.exists():
        logger.info(f"Loading MITRE STIX from cache: {CACHE_PATH}")
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    logger.info("Downloading MITRE ATT&CK STIX from GitHub...")
    resp = requests.get(MITRE_STIX_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f)
    logger.info(f"Cached STIX data to {CACHE_PATH}")
    return data


def parse_mitre_entries(stix_data: Dict) -> List[Dict]:
    """
    Parse all techniques and sub-techniques from STIX data.
    Returns list of dicts with: id, name, description, tactic(s),
    parent_id (for sub-techniques), is_subtechnique.

    Tactic entries include {shortname, name, tactic_id} sourced directly
    from the STIX x-mitre-tactic objects — no secondary mapping needed.
    """
    # Build tactic shortname → {name, tactic_id} from the STIX tactic objects.
    # x-mitre-tactic objects have external_references with the TA-XXXX ID.
    tactic_map: Dict[str, Dict[str, str]] = {}
    for obj in stix_data["objects"]:
        if obj["type"] != "x-mitre-tactic":
            continue
        shortname = obj.get("x_mitre_shortname", "")
        if not shortname:
            continue
        # Extract TA-XXXX from external_references
        tactic_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tactic_id = ref.get("external_id")  # e.g. "TA0006"
                break
        tactic_map[shortname] = {
            "shortname": shortname,
            "name": obj.get("name", shortname),
            "tactic_id": tactic_id,
        }

    if tactic_map:
        logger.info(
            f"Loaded {len(tactic_map)} tactics from STIX: "
            + ", ".join(f"{v['tactic_id']}={k}" for k, v in sorted(tactic_map.items()))
        )
    else:
        logger.warning("No x-mitre-tactic objects found in STIX data!")

    entries = []
    for obj in stix_data["objects"]:
        if obj["type"] != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue

        # Extract external ID (T1110 or T1110.001)
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break
        if not tech_id:
            continue

        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
        parent_id = tech_id.split(".")[0] if is_subtechnique else None

        # Tactics — each entry has {shortname, name, tactic_id} from the tactic_map
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                shortname = phase.get("phase_name", "")
                if shortname in tactic_map:
                    tactics.append(tactic_map[shortname])   # already has tactic_id
                else:
                    # Unexpected tactic shortname — include with None ID so we can see it
                    logger.warning(
                        f"Technique {tech_id}: unknown tactic shortname '{shortname}' "
                        "not found in x-mitre-tactic objects"
                    )
                    tactics.append({"shortname": shortname, "name": shortname, "tactic_id": None})

        name = obj.get("name", "")
        description = obj.get("description", "")
        platforms = obj.get("x_mitre_platforms", [])
        data_sources = obj.get("x_mitre_data_sources", [])

        # Build rich text for embedding — more context = better semantic match
        # BGE-large-v1.5: prepend passage prefix for asymmetric retrieval
        core_text = (
            f"MITRE ATT&CK {'Sub-technique' if is_subtechnique else 'Technique'}: "
            f"{tech_id} {name}. "
            f"Tactics: {', '.join(t['name'] for t in tactics)}. "
            f"Platforms: {', '.join(platforms)}. "
            f"Description: {description[:500]}"
        )
        embed_text = BGE_PASSAGE_PREFIX + core_text

        entries.append({
            "id": tech_id,
            "name": name,
            "description": description,
            "tactics": tactics,                                              # [{shortname, name, tactic_id}, ...]
            "primary_tactic": tactics[0]["shortname"] if tactics else "unknown",
            "primary_tactic_name": tactics[0]["name"] if tactics else "Unknown",
            "primary_tactic_id": tactics[0]["tactic_id"] if tactics else None,  # TA-XXXX
            "is_subtechnique": is_subtechnique,
            "parent_id": parent_id,
            "platforms": platforms,
            "data_sources": data_sources,
            "embed_text": embed_text,
        })

    logger.info(
        f"Parsed {len(entries)} entries "
        f"({sum(1 for e in entries if not e['is_subtechnique'])} techniques, "
        f"{sum(1 for e in entries if e['is_subtechnique'])} sub-techniques)"
    )
    return entries


# ── Embedding ────────────────────────────────────────────────────────────────

def generate_embeddings(entries: List[Dict]) -> List[List[float]]:
    """Generate sentence-transformer embeddings for all entries.

    Uses a local .npy cache so reruns skip the ~90s CPU step.
    Delete mitre_embeddings_cache.npy to force regeneration.
    """
    import numpy as np

    if EMBEDDING_CACHE_PATH.exists():
        logger.info(f"Loading embeddings from cache: {EMBEDDING_CACHE_PATH}")
        embeddings = np.load(str(EMBEDDING_CACHE_PATH))
        if len(embeddings) == len(entries):
            logger.info(f"Cache hit: {len(embeddings)} embeddings loaded.")
            return embeddings.tolist()
        else:
            logger.warning(
                f"Cache size mismatch ({len(embeddings)} cached vs {len(entries)} entries). "
                "Regenerating embeddings."
            )

    from sentence_transformers import SentenceTransformer

    logger.info(f"Loading embedding model: {EMBEDDING_MODEL}")
    model = SentenceTransformer(EMBEDDING_MODEL)

    texts = [e["embed_text"] for e in entries]
    logger.info(f"Generating embeddings for {len(texts)} entries (batch={BATCH_SIZE})...")

    embeddings = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        normalize_embeddings=True,  # Cosine similarity via dot product
        convert_to_numpy=True
    )
    logger.info(f"Generated {len(embeddings)} embeddings, shape: {embeddings.shape}")

    # Save to cache
    EMBEDDING_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    np.save(str(EMBEDDING_CACHE_PATH), embeddings)
    logger.info(f"Saved embedding cache to {EMBEDDING_CACHE_PATH}")

    return embeddings.tolist()


# ── Qdrant Loading ───────────────────────────────────────────────────────────

def load_into_qdrant(entries: List[Dict], embeddings: List[List[float]]):
    """Create Qdrant collection and upsert all MITRE entries.

    The QdrantClient is instantiated here (not at module level) so we always
    open a fresh connection — avoids idle timeout after the long embedding step.
    """
    from qdrant_client import QdrantClient
    from qdrant_client.models import (
        Distance, VectorParams, PointStruct,
        PayloadSchemaType
    )

    logger.info(f"Connecting to Qdrant at {QDRANT_HOST}:{QDRANT_PORT}")
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=30, prefer_grpc=False)

    # Delete existing collection if present (fresh index)
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION_NAME in existing:
        logger.info(f"Deleting existing collection: {COLLECTION_NAME}")
        client.delete_collection(COLLECTION_NAME)

    # Create collection
    logger.info(f"Creating collection: {COLLECTION_NAME} (dim={VECTOR_SIZE})")
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
    )

    # Build points
    points = []
    for i, (entry, embedding) in enumerate(zip(entries, embeddings)):
        # Use integer ID (Qdrant requires int or UUID)
        point_id = i + 1
        payload = {k: v for k, v in entry.items() if k != "embed_text"}
        points.append(PointStruct(id=point_id, vector=embedding, payload=payload))

    # Upsert in batches
    logger.info(f"Upserting {len(points)} points into Qdrant...")
    for i in range(0, len(points), BATCH_SIZE):
        batch = points[i : i + BATCH_SIZE]
        client.upsert(collection_name=COLLECTION_NAME, points=batch)
        logger.info(f"  Upserted {min(i + BATCH_SIZE, len(points))}/{len(points)}")

    # Create payload indexes for fast filtering
    client.create_payload_index(COLLECTION_NAME, "is_subtechnique", PayloadSchemaType.BOOL)
    client.create_payload_index(COLLECTION_NAME, "parent_id", PayloadSchemaType.KEYWORD)
    client.create_payload_index(COLLECTION_NAME, "primary_tactic", PayloadSchemaType.KEYWORD)

    # Verify
    info = client.get_collection(COLLECTION_NAME)
    logger.info(f"✅ Collection '{COLLECTION_NAME}' ready: {info.points_count} points")


# ── Save ID→Entry lookup ─────────────────────────────────────────────────────

def save_id_lookup(entries: List[Dict]):
    """Save technique_id → entry dict for fast O(1) lookup at runtime."""
    lookup = {e["id"]: e for e in entries}
    lookup_path = Path(__file__).parent.parent.parent / "backend" / "services" / "enrichment" / "mitre_data" / "mitre_id_lookup.pkl"
    with open(lookup_path, "wb") as f:
        pickle.dump(lookup, f)
    logger.info(f"Saved ID lookup ({len(lookup)} entries) to {lookup_path}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 60)
    logger.info("MITRE ATT&CK → Qdrant Indexer")
    logger.info("=" * 60)

    # 1. Download STIX
    stix_data = download_mitre_stix()

    # 2. Parse entries
    entries = parse_mitre_entries(stix_data)
    if not entries:
        logger.error("No entries parsed. Aborting.")
        sys.exit(1)

    # 3. Generate embeddings
    embeddings = generate_embeddings(entries)

    # 4. Load into Qdrant
    load_into_qdrant(entries, embeddings)

    # 5. Save ID lookup
    save_id_lookup(entries)

    logger.info("=" * 60)
    logger.info("✅ MITRE indexing complete!")
    logger.info(f"   Collection: {COLLECTION_NAME}")
    logger.info(f"   Entries: {len(entries)}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
