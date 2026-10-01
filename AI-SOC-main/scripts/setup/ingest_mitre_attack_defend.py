"""
MITRE ATT&CK + D3FEND Ingest Script
=====================================
Builds the `mitre_attack_defend` Qdrant collection.

For each ATT&CK technique:
  1. Pull official mitigations from STIX cache (already downloaded)
  2. Pull D3FEND countermeasures from D3FEND REST API
  3. Build rich defensive_summary text for embedding
  4. Store with direct technique_id lookup payload

Primary retrieval in production = direct scroll by technique_id (O(1)).
Semantic search used only as fallback for unmapped sub-techniques.

Run:
    python scripts/setup/ingest_mitre_attack_defend.py
"""

import json
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests  # sync HTTP for setup script (not async)
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent.parent
STIX_CACHE = ROOT / "backend" / "services" / "enrichment" / "mitre_data" / "mitre_stix_cache.json"

QDRANT_HOST     = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT     = int(os.getenv("QDRANT_PORT", "6333"))
COLLECTION_NAME = "mitre_attack_defend"
EMBEDDING_MODEL = "BAAI/bge-large-en-v1.5"
BGE_PASSAGE_PREFIX = "Represent this sentence for searching relevant passages: "
VECTOR_SIZE     = 1024
BATCH_SIZE      = 32

D3FEND_API_BASE = "https://d3fend.mitre.org/api/offensive-technique/attack/{tech_id}.json"
D3FEND_CACHE_PATH = ROOT / "backend" / "services" / "knowledge_base" / "data" / "d3fend_cache.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ── D3FEND API ─────────────────────────────────────────────────────────────────

def load_d3fend_cache() -> Dict[str, Any]:
    D3FEND_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if D3FEND_CACHE_PATH.exists():
        with open(D3FEND_CACHE_PATH, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_d3fend_cache(cache: Dict[str, Any]):
    with open(D3FEND_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)


def fetch_d3fend(tech_id: str, cache: Dict[str, Any]) -> List[Dict]:
    """
    Fetch D3FEND countermeasures for a given ATT&CK technique ID.
    Returns list of {id, label, definition, category}.
    Uses local cache to avoid redundant API calls.
    """
    if tech_id in cache:
        return cache[tech_id]

    url = D3FEND_API_BASE.format(tech_id=tech_id)
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            cache[tech_id] = []
            return []
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.debug(f"D3FEND API error for {tech_id}: {e}")
        cache[tech_id] = []
        return []

    # Parse D3FEND response schema
    techniques = []
    # D3FEND returns: {"@context": ..., "offensive-technique": {...}}
    hits = data.get("offensive-technique", {})
    d3fend_list = hits.get("d3fend-countermeasure", [])
    if isinstance(d3fend_list, dict):
        d3fend_list = [d3fend_list]

    for item in d3fend_list:
        label    = item.get("label", item.get("d3fend-id", ""))
        d3f_id   = item.get("d3fend-id", "")
        defn     = item.get("definition", "")
        cat_raw  = item.get("top-level-category", "")

        # Map D3FEND top-level category
        cat_map = {
            "model": "Detect", "harden": "Harden", "isolate": "Isolate",
            "deceive": "Deceive", "evict": "Evict", "detect": "Detect",
        }
        category = cat_map.get(cat_raw.lower(), cat_raw.title() or "Unknown")

        techniques.append({
            "id": d3f_id, "label": label,
            "definition": defn[:400], "category": category,
        })

    cache[tech_id] = techniques
    return techniques


# ── STIX Parsing ───────────────────────────────────────────────────────────────

def parse_stix(stix_path: Path) -> Dict[str, Any]:
    """
    Extract techniques and mitigations from STIX bundle.
    Returns {technique_id: {name, tactic, description, detection, mitigations[]}}
    """
    logger.info("Parsing STIX cache...")
    with open(stix_path, encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    techniques: Dict[str, Dict] = {}
    mitigations: Dict[str, Dict] = {}
    relationships: List[Dict] = []

    for obj in objects:
        otype = obj.get("type", "")
        if otype == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            tech_id = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), None
            )
            if not tech_id:
                continue
            tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                       if p.get("kill_chain_name") == "mitre-attack"]
            techniques[obj["id"]] = {
                "tech_id":     tech_id,
                "name":        obj.get("name", ""),
                "description": obj.get("description", "")[:600],
                "detection":   obj.get("x_mitre_detection", "")[:400],
                "tactic":      tactics[0] if tactics else "unknown",
                "tactic_list": tactics,
                "platforms":   obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "mitigations": [],
            }
        elif otype == "course-of-action":
            mitigations[obj["id"]] = {
                "name":        obj.get("name", ""),
                "description": obj.get("description", "")[:500],
                "mit_id":      next(
                    (r["external_id"] for r in obj.get("external_references", [])
                     if r.get("source_name") == "mitre-attack"), ""
                ),
            }
        elif otype == "relationship" and obj.get("relationship_type") == "mitigates":
            relationships.append({
                "source": obj.get("source_ref", ""),
                "target": obj.get("target_ref", ""),
            })

    # Attach mitigations to techniques
    for rel in relationships:
        mit = mitigations.get(rel["source"])
        tech = techniques.get(rel["target"])
        if mit and tech:
            tech["mitigations"].append(mit)

    logger.info(f"STIX: {len(techniques)} techniques with {sum(len(t['mitigations']) for t in techniques.values())} mitigation links")
    return {t["tech_id"]: t for t in techniques.values()}


# ── Build Defensive Summary ────────────────────────────────────────────────────

def build_defensive_summary(tech_id: str, tech: Dict, d3fend: List[Dict]) -> str:
    parts = [
        f"MITRE ATT&CK {tech_id}: {tech['name']}.",
        f"Tactic: {tech['tactic'].replace('-', ' ').title()}.",
        f"Platforms: {', '.join(tech['platforms'][:4])}.",
    ]
    if d3fend:
        cats = list({d["category"] for d in d3fend})
        names = [d["label"] for d in d3fend[:5]]
        parts.append(f"D3FEND countermeasures ({', '.join(cats)}): {'; '.join(names)}.")
    if tech["mitigations"]:
        mit_names = [m["name"] for m in tech["mitigations"][:4]]
        parts.append(f"ATT&CK mitigations: {'; '.join(mit_names)}.")
    if tech.get("detection"):
        parts.append(f"Detection: {tech['detection'][:200]}")
    return " ".join(parts)


# ── Main ───────────────────────────────────────────────────────────────────────

def setup_collection(client: QdrantClient):
    try:
        client.get_collection(COLLECTION_NAME)
        logger.info(f"Collection '{COLLECTION_NAME}' exists.")
        return
    except Exception:
        pass
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
    )
    logger.info(f"Created collection '{COLLECTION_NAME}'.")


def main():
    if not STIX_CACHE.exists():
        logger.error(f"STIX cache not found: {STIX_CACHE}")
        logger.error("Run scripts/setup/index_mitre_to_qdrant.py first.")
        sys.exit(1)

    client  = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=60)
    setup_collection(client)

    logger.info(f"Loading {EMBEDDING_MODEL}...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    techniques = parse_stix(STIX_CACHE)
    d3fend_cache = load_d3fend_cache()

    points: List[PointStruct] = []
    total = len(techniques)

    logger.info(f"Processing {total} techniques (STIX + D3FEND API)...")

    texts_for_embed: List[str] = []
    meta_list: List[Dict] = []
    
    for i, (tech_id, tech) in enumerate(techniques.items(), 1):
        # Fetch D3FEND (cached after first run)
        d3fend = fetch_d3fend(tech_id, d3fend_cache)
        if i % 50 == 0:
            save_d3fend_cache(d3fend_cache)
            logger.info(f"  D3FEND: {i}/{total} techniques processed, cache saved")
        time.sleep(0.05)  # gentle rate limiting

        d3fend_categories = list({d["category"] for d in d3fend})
        defensive_summary = build_defensive_summary(tech_id, tech, d3fend)

        texts_for_embed.append(BGE_PASSAGE_PREFIX + defensive_summary)
        meta_list.append({
            "technique_id":       tech_id,
            "technique_name":     tech["name"],
            "tactic":             tech["tactic"],
            "tactic_list":        tech["tactic_list"],
            "is_subtechnique":    tech["is_subtechnique"],
            "platforms":          tech["platforms"],
            "description":        tech["description"],
            "detection_guidance": tech["detection"],
            "d3fend_techniques":  [
                {"id": d["id"], "label": d["label"], "definition": d["definition"], "category": d["category"]}
                for d in d3fend
            ],
            "d3fend_categories":  d3fend_categories,
            "attack_mitigations": [
                {"mitigation_id": m["mit_id"], "name": m["name"], "description": m["description"]}
                for m in tech["mitigations"]
            ],
            "defensive_summary": defensive_summary,
        })

    # Save full D3FEND cache
    save_d3fend_cache(d3fend_cache)
    logger.info(f"D3FEND cache saved to {D3FEND_CACHE_PATH}")

    # Embed all defensive summaries in batches
    logger.info(f"Embedding {len(texts_for_embed)} defensive summaries...")
    embeddings = model.encode(
        texts_for_embed, batch_size=BATCH_SIZE,
        show_progress_bar=True, normalize_embeddings=True
    )

    # Build Qdrant points
    for meta, emb in zip(meta_list, embeddings):
        pid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"defend_{meta['technique_id']}"))
        points.append(PointStruct(
            id=pid, vector=emb.tolist(), payload=meta
        ))

    # Upsert with retry
    logger.info(f"Upserting {len(points)} points to Qdrant...")
    UPSERT_BATCH = 32
    failed_batches = 0
    for i in range(0, len(points), UPSERT_BATCH):
        batch = points[i:i + UPSERT_BATCH]
        for attempt in range(3):
            try:
                client.upsert(collection_name=COLLECTION_NAME, points=batch)
                logger.info(f"  Upserted {min(i + UPSERT_BATCH, len(points))}/{len(points)}")
                break
            except Exception as e:
                if attempt < 2:
                    wait = 2 ** attempt
                    logger.warning(f"  Upsert failed (attempt {attempt+1}), retrying in {wait}s: {e}")
                    time.sleep(wait)
                else:
                    logger.error(f"  Upsert permanently failed for batch {i//UPSERT_BATCH}: {e}")
                    failed_batches += 1
    if failed_batches:
        logger.warning(f"⚠️  {failed_batches} batches failed — rerun to retry")

    logger.info(f"\n✅ mitre_attack_defend collection ready: {len(points)} techniques")
    logger.info(f"   D3FEND cache: {len(d3fend_cache)} entries at {D3FEND_CACHE_PATH}")


if __name__ == "__main__":
    main()
