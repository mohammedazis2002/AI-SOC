import os, yaml, json, uuid, re, time, requests
from pathlib import Path
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer

# Suppress tokenizer parallelism warning on macOS
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# ── Config from Env Vars ──────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, fallback to system env vars

QDRANT_HOST      = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT      = int(os.getenv("QDRANT_PORT", "6333"))
QDRANT_API_KEY   = os.getenv("QDRANT_API_KEY")
COLLECTION_NAME  = "playbooks"
SOURCES_DIR      = Path(__file__).parent

# ── Clients ───────────────────────────────────────────────────────────────────
print("Loading embedding model (first run may take a few minutes)...")
api_key_val = QDRANT_API_KEY if QDRANT_API_KEY else None
client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, api_key=api_key_val)
# Using all-MiniLM-L6-v2 (~90MB) to ensure fast download.
# Swap back to "BAAI/bge-large-en-v1.5" (+ size=1024) once you've pre-downloaded it.
MODEL_NAME = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
VECTOR_SIZE = 384  # 384 for MiniLM; change to 1024 if using bge-large
model  = SentenceTransformer(MODEL_NAME)
print("Model loaded.\n")

# ── CACAO 2.0 Phase Mapping ───────────────────────────────────────────────────
PHASE_MAP = {
    "initial-access":        "detection",
    "execution":             "detection",
    "persistence":           "containment",
    "privilege-escalation":  "containment",
    "defense-evasion":       "containment",
    "credential-access":     "containment",
    "discovery":             "detection",
    "lateral-movement":      "containment",
    "collection":            "containment",
    "command-and-control":   "eradication",
    "exfiltration":          "eradication",
    "impact":                "recovery",
}

def phase_from_tactic(tactic: str) -> str:
    return PHASE_MAP.get(tactic.lower(), "detection")

# ── Collection Setup ──────────────────────────────────────────────────────────
def setup_collection():
    if client.collection_exists(COLLECTION_NAME):
        client.delete_collection(COLLECTION_NAME)
        print(f"Deleted existing collection '{COLLECTION_NAME}'.")
    
    # replication_factor=1 for single-node local; increase for cluster
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        replication_factor=1,
        shard_number=2,
    )
    print(f"Created collection '{COLLECTION_NAME}'.")

# ── Batch Upsert Helper ───────────────────────────────────────────────────────
def upsert_batch(points: list):
    if not points:
        return
    client.upsert(collection_name=COLLECTION_NAME, points=points)

def embed(text: str) -> list:
    return model.encode(text, normalize_embeddings=True).tolist()

# ── Source 1: MITRE ATT&CK ───────────────────────────────────────────────────
def ingest_attack():
    print("[1/5] Ingesting MITRE ATT&CK (Remediation/Mitigations only)...")
    attack_file = SOURCES_DIR.parent / "data" / "mitre" / "enterprise-attack.json"
    if not attack_file.exists():
        print("  ✗ enterprise-attack.json not found, skipping.\n")
        return

    with open(attack_file) as f:
        data = json.load(f)

    # We only want "course-of-action" (Remediations/Mitigations)
    coas = [
        o for o in data["objects"]
        if o.get("type") == "course-of-action" and not o.get("revoked")
    ]

    points, count = [], 0
    for coa in coas:
        ext_refs   = coa.get("external_references", [])
        coa_id     = next((r.get("external_id", "unknown") for r in ext_refs if r.get("source_name") == "mitre-attack"), "unknown")
        if not coa_id.startswith("M"):
            continue

        name       = coa.get("name", "")
        description= coa.get("description", "")
        
        # All mitigations aim for containment/eradication/hardening
        phase = "containment"

        text = f"{coa_id}: {name}\n{description}"
        payload = {
            "source":          "mitre-attack",
            "technique_id":    coa_id,
            "name":            name,
            "description":     description[:500],
            "phase":           phase,
            "cacao_type":      "mitigation-playbook",
            "tier":            2,
        }
        uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"attack-coa-{coa_id}"))
        points.append(PointStruct(id=uid, vector=embed(text), payload=payload))
        count += 1
        if len(points) >= 50:
            upsert_batch(points)
            points = []
            print(f"  ... {count} mitigations processed", end="\r")

    upsert_batch(points)
    print(f"  ✓ ATT&CK: {count} remediations ingested.")

# ── Source 2: Atomic Red Team ─────────────────────────────────────────────────
def ingest_art():
    print("[2/5] Ingesting Atomic Red Team (Cleanup/Remediation only)...")
    art_dir = SOURCES_DIR / "atomic-red-team" / "atomics"
    if not art_dir.exists():
        print("  ✗ atomic-red-team/atomics not found, skipping.\n")
        return

    points, count = [], 0
    for yaml_file in sorted(art_dir.rglob("*.yaml")):
        if yaml_file.stem != yaml_file.parent.name:
            continue
        try:
            with open(yaml_file, errors="ignore") as f:
                data = yaml.safe_load(f)
            if not data or "atomic_tests" not in data:
                continue

            tech_id      = data.get("attack_technique", "")
            display_name = data.get("display_name", "")

            for test in data.get("atomic_tests", []):
                test_name   = test.get("name", "")
                platforms   = test.get("supported_platforms", [])
                executor    = test.get("executor", {})
                
                # ONLY fetch cleanup commands (remediations)
                cleanup_command = executor.get("cleanup_command")
                if not cleanup_command:
                    continue

                text = f"{tech_id} Cleanup: {display_name} - {test_name}\nRemediation Command: {cleanup_command}"
                payload = {
                    "source":      "atomic-red-team",
                    "technique_id":tech_id,
                    "name":        f"{display_name} (Cleanup): {test_name}",
                    "description": "Atomic Red Team cleanup/remediation steps for the simulated test.",
                    "phase":       "eradication",  # specific to cleanup/restore
                    "platforms":   platforms,
                    "command":     str(cleanup_command)[:400],
                    "cacao_type":  "mitigation-playbook",
                    "tier":        3,
                }
                uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"art-cleanup-{tech_id}-{test_name}"))
                points.append(PointStruct(id=uid, vector=embed(text), payload=payload))
                count += 1
                if len(points) >= 50:
                    upsert_batch(points)
                    points = []
                    print(f"  ... {count} remediations processed", end="\r")
        except Exception as e:
            print(f"  ✗ Error parsing {yaml_file.name}: {e}")

    upsert_batch(points)
    print(f"  ✓ Atomic Red Team: {count} cleanup/remediation steps ingested.")


# ── Source 5: MITRE D3FEND (live API) ────────────────────────────────────────
def ingest_d3fend():
    print("[5/5] Ingesting MITRE D3FEND (live API)...")
    url = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"
    try:
        resp = requests.get(url, timeout=90)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"  ✗ Could not fetch D3FEND API: {e}\n")
        return

    bindings = data.get("results", {}).get("bindings", [])
    points, count, seen = [], 0, set()

    for binding in bindings:
        try:
            def_label = binding.get("def_tech_label", {}).get("value", "")
            off_label = binding.get("off_tech_label", {}).get("value", "")
            off_id    = binding.get("off_tech_id",    {}).get("value", "")
            def_id    = binding.get("def_tech_id",    {}).get("value", "")

            key = f"{def_id}|{off_id}"
            if key in seen or not def_label:
                continue
            seen.add(key)

            # ONLY Include Isolate, Harden, Evict features
            lbl = def_label.lower()
            if any(k in lbl for k in ("isolat", "contain", "block", "restrict", "filter")):
                phase = "containment" # Isolate
            elif any(k in lbl for k in ("remov", "eradicat", "clean", "patch", "evict")):
                phase = "eradication" # Evict
            elif any(k in lbl for k in ("harden", "restor", "recover", "backup")):
                phase = "recovery"    # Harden
            else:
                # If it's a 'detect', 'monitor', 'analyze' or others, skip it
                continue

            text = f"D3FEND: {def_label}\nCounters ATT&CK: {off_label} ({off_id})"
            payload = {
                "source":           "d3fend",
                "name":             def_label,
                "description":      f"D3FEND countermeasure '{def_label}' counters '{off_label}'",
                "phase":            phase,
                "technique_id":     off_id,
                "defense_technique":def_label,
                "defense_id":       def_id,
                "cacao_type":       "mitigation-playbook",
                "tier":             2,
            }
            uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"d3fend-{key}"))
            points.append(PointStruct(id=uid, vector=embed(text), payload=payload))
            count += 1
            if len(points) >= 50:
                upsert_batch(points)
                points = []
        except Exception:
            pass

    upsert_batch(points)
    print(f"  ✓ D3FEND: {count} countermeasure mappings ingested.")

# ── Validation Query ──────────────────────────────────────────────────────────
def validate():
    print("\n── Validation: searching for T1110 (Brute Force) ──")
    query_vec = embed("T1110 Brute Force credential attack detection containment")
    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vec,
        limit=3,
        with_payload=True,
    ).points
    if results:
        for r in results:
            p = r.payload
            print(f"  [{r.score:.3f}] [{p.get('source','?')}] {p.get('name','?')}")
            print(f"           phase={p.get('phase','?')} | tier={p.get('tier','?')}")
            if p.get("detection_hints"):
                print(f"           detection_hints: {p['detection_hints'][:80]}...")
    else:
        print("  No results found — check ingestion.")

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  Playbook KB Ingestion (CACAO 2.0 format)")
    print(f"  Qdrant: {QDRANT_HOST}:{QDRANT_PORT}")
    print("=" * 55 + "\n")

    setup_collection()

    start = time.time()
    ingest_attack()
    ingest_art()
    ingest_d3fend()
    elapsed = time.time() - start

    info = client.get_collection(COLLECTION_NAME)
    print(f"\n{'='*55}")
    print(f"  Ingestion Complete!")
    print(f"  Total vectors: {info.points_count}")
    print(f"  Time elapsed:  {elapsed:.1f}s")
    print(f"{'='*55}\n")

    validate()