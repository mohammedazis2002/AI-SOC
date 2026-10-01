"""
Historical Incidents Ingest Script
=====================================
Ingest pipeline for the `historical_incidents` Qdrant collection.

Accepts:
  - JSON file (array of incident objects)
  - CSV file with columns: incident_id, summary, mitre_technique, resolution, outcome, analyst_approved, timestamp

The collection starts empty and grows as real incidents are analyst-approved.
This script is used for bulk-loading the 90-day historical data when available.

Run:
    python scripts/setup/ingest_historical_incidents.py --input path/to/incidents.json
    python scripts/setup/ingest_historical_incidents.py --input path/to/incidents.csv
"""

import argparse
import csv
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

QDRANT_HOST     = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT     = int(os.getenv("QDRANT_PORT", "6333"))
COLLECTION_NAME = "historical_incidents"
EMBEDDING_MODEL = "BAAI/bge-large-en-v1.5"
BGE_PASSAGE_PREFIX = "Represent this sentence for searching relevant passages: "
VECTOR_SIZE     = 1024
BATCH_SIZE      = 32

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


REQUIRED_FIELDS = ["summary"]


def load_incidents(path: Path) -> List[Dict]:
    ext = path.suffix.lower()
    if ext == ".json":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data]
    elif ext == ".csv":
        incidents = []
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                incidents.append(dict(row))
        return incidents
    else:
        raise ValueError(f"Unsupported file format: {ext}. Use .json or .csv")


def validate_incident(inc: Dict) -> bool:
    for field in REQUIRED_FIELDS:
        if not inc.get(field, "").strip():
            return False
    return True


def build_embed_text(inc: Dict) -> str:
    """Rich text for embedding: summary + technique + resolution."""
    tech = inc.get("mitre_technique", "")
    res  = inc.get("resolution", "")
    outcome = inc.get("outcome", "")
    return (
        f"Incident: {inc.get('summary', '')}. "
        f"{'Technique: ' + tech + '. ' if tech else ''}"
        f"{'Resolution: ' + res + '. ' if res else ''}"
        f"{'Outcome: ' + outcome if outcome else ''}"
    ).strip()


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


def create_empty_collection():
    """Create the collection structure without ingesting any data.
    Called when no input file is provided (initial setup — data will come later)."""
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    setup_collection(client)
    logger.info("✅ historical_incidents collection created (empty — ready for 90-day data)")


def ingest(input_path: Path):
    logger.info(f"Loading incidents from {input_path}")
    incidents = load_incidents(input_path)
    logger.info(f"Loaded {len(incidents)} incidents")

    valid = [i for i in incidents if validate_incident(i)]
    skipped = len(incidents) - len(valid)
    if skipped:
        logger.warning(f"Skipped {skipped} invalid incidents (missing 'summary')")
    logger.info(f"Ingesting {len(valid)} valid incidents")

    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    setup_collection(client)

    logger.info(f"Loading {EMBEDDING_MODEL}...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    texts = [BGE_PASSAGE_PREFIX + build_embed_text(i) for i in valid]
    logger.info(f"Embedding {len(texts)} incidents...")
    embeddings = model.encode(texts, batch_size=BATCH_SIZE, show_progress_bar=True, normalize_embeddings=True)

    points: List[PointStruct] = []
    for inc, emb in zip(valid, embeddings):
        inc_id = str(inc.get("incident_id", uuid.uuid4()))
        pid = str(uuid.uuid5(uuid.NAMESPACE_DNS, inc_id))

        # Parse timestamp
        ts = inc.get("timestamp")
        if isinstance(ts, str):
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(ts).timestamp()
            except Exception:
                ts = None

        points.append(PointStruct(
            id=pid,
            vector=emb.tolist(),
            payload={
                "incident_id":      inc_id,
                "summary":          inc.get("summary", "")[:1000],
                "mitre_technique":  inc.get("mitre_technique", ""),
                "resolution":       inc.get("resolution", "")[:500],
                "outcome":          inc.get("outcome", "resolved"),
                "analyst_approved": str(inc.get("analyst_approved", "true")).lower() == "true",
                "severity":         inc.get("severity", ""),
                "asset_type":       inc.get("asset_type", ""),
                "source_ip":        inc.get("source_ip", ""),
                "timestamp":        ts,
            }
        ))

    for i in range(0, len(points), BATCH_SIZE):
        batch = points[i:i + BATCH_SIZE]
        client.upsert(collection_name=COLLECTION_NAME, points=batch)
        logger.info(f"  Upserted {min(i+BATCH_SIZE,len(points))}/{len(points)}")

    logger.info(f"✅ Ingested {len(points)} incidents into '{COLLECTION_NAME}'")


def main():
    parser = argparse.ArgumentParser(description="Ingest historical incidents into Qdrant")
    parser.add_argument("--input", type=str, default=None,
                        help="Path to incidents JSON or CSV file. Omit to just create empty collection.")
    args = parser.parse_args()

    if args.input:
        ingest(Path(args.input))
    else:
        create_empty_collection()


if __name__ == "__main__":
    main()
