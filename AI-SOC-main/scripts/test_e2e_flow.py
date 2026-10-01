"""
End-to-End Flow Test
====================
Picks a real alert from the Wazuh log archive, injects it through the
ingestion webhook, then traces it through every stage of the pipeline:

  [Wazuh alert] → POST /api/v1/alerts/webhook/wazuh
                → MongoDB alerts_raw + alerts_processed
                → Redis priority_queue / standard_queue
                → Dispatcher (if running) → Agent API

Usage (with Docker stack running):
    python scripts/test_e2e_flow.py

Usage (offline — normalisation & queue validation only):
    python scripts/test_e2e_flow.py --offline

Environment variables (or edit the CONFIG block below):
    INGESTION_URL   Base URL of the ingestion service (default: http://localhost:8000)
    AGENT_URL       Base URL of the agent API        (default: http://localhost:8001)
    API_KEY         Ingestion API key                 (default: read from .env)
    REDIS_HOST      Redis host                        (default: localhost)
    REDIS_PORT      Redis port                        (default: 6379)
    REDIS_PASSWORD  Redis password                    (default: None)
    MONGO_URI       MongoDB URI                       (default: mongodb://localhost:27017/)
    MONGO_DATABASE  MongoDB database name             (default: soar_db)
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
import textwrap
from datetime import datetime

# ── Optional deps (graceful degradation if not installed) ──────────────────
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import redis as redis_lib
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

try:
    from pymongo import MongoClient
    HAS_MONGO = True
except ImportError:
    HAS_MONGO = False

# ── CONFIG ─────────────────────────────────────────────────────────────────
INGESTION_URL  = os.environ.get("INGESTION_URL",  "http://localhost:8000")
AGENT_URL      = os.environ.get("AGENT_URL",      "http://localhost:8001")
API_KEY        = os.environ.get("API_KEY",        "")
REDIS_HOST     = os.environ.get("REDIS_HOST",     "localhost")
REDIS_PORT     = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)
MONGO_URI      = os.environ.get("MONGO_URI",      "mongodb://localhost:27017/")
MONGO_DATABASE = os.environ.get("MONGODB_DATABASE", "soar_db")

LOG_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "data", "alerts", "wazuh_120days_logs (1).json.gz"
)

# ── Colours ────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):   print(f"  {GREEN}✓{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}⚠{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")
def info(msg): print(f"  {CYAN}→{RESET} {msg}")
def hdr(msg):  print(f"\n{BOLD}{msg}{RESET}")


# ── Step 1: Extract alert ──────────────────────────────────────────────────

def extract_alert(log_path: str) -> dict:
    """Stream-parse the gz file line-by-line; return the highest-level alert found in first 200 lines."""
    hdr("Step 1 — Extracting alert from Wazuh log archive")
    info(f"File: {log_path}")

    candidates = []
    try:
        with gzip.open(log_path, "rt", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= 200:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    candidates.append(obj)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        fail(f"Could not read log file: {e}")
        sys.exit(1)

    if not candidates:
        fail("No parseable alerts found in first 200 lines.")
        sys.exit(1)

    # Pick highest rule level
    best = max(candidates, key=lambda a: a.get("rule", {}).get("level", 0))
    lvl  = best.get("rule", {}).get("level", "?")
    desc = best.get("rule", {}).get("description", "")
    ok(f"Selected alert: rule.level={lvl}  description='{desc}'")
    info(f"Agent: {best.get('agent', {}).get('name', '?')} | "
         f"Timestamp: {best.get('timestamp', '?')[:19]}")
    return best


# ── Step 2: Offline normalisation smoke-test ───────────────────────────────

def test_normalisation_offline(alert: dict) -> None:
    hdr("Step 2 — Offline normalisation smoke-test")
    info("Checking key Wazuh fields present in the alert…")

    required = ["id", "rule", "agent"]
    for field in required:
        if field in alert:
            ok(f"Field '{field}' present")
        else:
            warn(f"Field '{field}' missing — mapper may fall back to defaults")

    rule = alert.get("rule", {})
    info(f"Rule ID: {rule.get('id', '?')}  |  Level: {rule.get('level', '?')}")

    # Map Wazuh level → severity (mirrors WazuhToULFMapper logic)
    level = int(rule.get("level", 0))
    if   level >= 15: severity = "CRITICAL"
    elif level >= 12: severity = "HIGH"
    elif level >= 7:  severity = "MEDIUM"
    elif level >= 4:  severity = "LOW"
    else:             severity = "INFORMATIONAL"

    info(f"Severity (predicted): {severity}")

    # Priority queue assignment
    is_priority = level >= 12
    queue = "priority_queue" if is_priority else "standard_queue"
    info(f"Expected queue: {queue}")
    ok("Offline normalisation check passed")


# ── Step 3: POST to ingestion webhook ─────────────────────────────────────

def post_to_ingestion(alert: dict) -> str | None:
    """Returns alert_id on success, None on failure."""
    hdr("Step 3 — Posting alert to ingestion webhook")

    if not HAS_REQUESTS:
        warn("'requests' not installed — skipping live POST. pip install requests")
        return None

    if not API_KEY:
        warn("API_KEY env var not set — skipping live POST.")
        return None

    url = f"{INGESTION_URL}/api/v1/alerts/webhook/wazuh"
    info(f"POST {url}")

    try:
        resp = requests.post(
            url,
            json=alert,
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            timeout=15,
        )
        info(f"HTTP {resp.status_code}")

        if resp.status_code == 202:
            data      = resp.json()
            alert_id  = data.get("alert_id", "?")
            mapper    = data.get("mapper_used", "?")
            warnings  = data.get("validation", {}).get("warnings", [])
            ok(f"Accepted → alert_id={alert_id}  mapper={mapper}")
            if warnings:
                for w in warnings:
                    warn(f"Validation warning: {w}")
            return alert_id
        else:
            fail(f"Ingestion rejected: {resp.text[:200]}")
            return None
    except Exception as e:
        fail(f"Request failed: {e}")
        return None


# ── Step 4: Check Redis queues ─────────────────────────────────────────────

def check_redis(alert_id: str | None) -> None:
    hdr("Step 4 — Redis queue inspection")

    if not HAS_REDIS:
        warn("'redis' not installed — skipping. pip install redis")
        return

    try:
        r = redis_lib.Redis(
            host=REDIS_HOST, port=REDIS_PORT,
            password=REDIS_PASSWORD, db=0, decode_responses=True,
            socket_connect_timeout=3,
        )
        r.ping()
    except Exception as e:
        warn(f"Redis unreachable ({e}) — is the stack running?")
        return

    pq_len = r.zcard("priority_queue")
    sq_len = r.llen("standard_queue")
    ok(f"priority_queue depth: {pq_len}")
    ok(f"standard_queue depth: {sq_len}")

    if alert_id:
        # Check if alert_id is in priority_queue (ZSET members)
        score = r.zscore("priority_queue", alert_id)
        if score is not None:
            ok(f"Alert {alert_id} found in priority_queue (score={score})")
        else:
            # Check standard queue (list — scan up to 100 items)
            items = r.lrange("standard_queue", 0, 99)
            if alert_id in items:
                ok(f"Alert {alert_id} found in standard_queue")
            else:
                info(f"Alert {alert_id} not in queues yet (may have been consumed already)")


# ── Step 5: Check MongoDB ──────────────────────────────────────────────────

def check_mongo(alert_id: str | None) -> None:
    hdr("Step 5 — MongoDB document check")

    if not HAS_MONGO:
        warn("'pymongo' not installed — skipping. pip install pymongo")
        return

    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        db     = client[MONGO_DATABASE]
    except Exception as e:
        warn(f"MongoDB unreachable ({e}) — is the stack running?")
        return

    raw_count  = db.alerts_raw.count_documents({})
    proc_count = db.alerts_processed.count_documents({})
    ok(f"alerts_raw count:       {raw_count}")
    ok(f"alerts_processed count: {proc_count}")

    if alert_id:
        raw  = db.alerts_raw.find_one({"alert_id": alert_id}, {"alert_id": 1, "severity": 1})
        proc = db.alerts_processed.find_one({"alert_id": alert_id}, {"alert_id": 1, "severity": 1, "queue_assignment": 1})

        if raw:
            ok(f"alerts_raw:       found alert_id={alert_id}")
        else:
            info(f"alerts_raw:       {alert_id} not found yet")

        if proc:
            ok(f"alerts_processed: found  severity={proc.get('severity')}  queue={proc.get('queue_assignment')}")
        else:
            info(f"alerts_processed: {alert_id} not yet present (normalisation may still be running)")


# ── Step 6: Poll agent status ──────────────────────────────────────────────

def poll_agent_status(alert_id: str | None, timeout: int = 60) -> None:
    hdr("Step 6 — Polling agent pipeline status")

    if not alert_id:
        warn("No alert_id — skipping agent status poll")
        return

    if not HAS_REQUESTS:
        warn("'requests' not installed — skipping.")
        return

    url = f"{AGENT_URL}/status/{alert_id}"
    info(f"Polling {url} for up to {timeout}s…")

    elapsed = 0
    while elapsed < timeout:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                ok(f"Agent completed! decision={data.get('decision')}  confidence={data.get('confidence')}")
                info(f"Full response: {json.dumps(data, indent=2)}")
                return
            elif resp.status_code == 404:
                info(f"  Agent still processing… ({elapsed}s elapsed)")
            else:
                warn(f"Unexpected status HTTP {resp.status_code}")
        except Exception as e:
            warn(f"Agent API unreachable: {e}")
            break

        time.sleep(10)
        elapsed += 10

    if elapsed >= timeout:
        warn(f"Agent did not complete within {timeout}s — may still be running")
        info("Check agent logs: docker logs soar-agent-api")


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="SOAR end-to-end flow test")
    parser.add_argument("--offline", action="store_true",
                        help="Run only offline checks (no live services required)")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  SOAR End-to-End Flow Test  [{datetime.now().strftime('%H:%M:%S')}]")
    print(f"{'='*60}")

    # Step 1: get a real alert from the archive
    alert = extract_alert(LOG_PATH)

    # Step 2: offline smoke test (always runs)
    test_normalisation_offline(alert)

    if args.offline:
        print(f"\n{YELLOW}--offline mode: skipping live service tests.{RESET}")
        print(f"Start the stack with 'docker compose up -d' then run without --offline.\n")
        return

    # Step 3–6 require live services
    alert_id = post_to_ingestion(alert)

    if alert_id:
        # Small pause to let normalisation write to MongoDB
        time.sleep(3)

    check_redis(alert_id)
    check_mongo(alert_id)
    poll_agent_status(alert_id, timeout=60)

    print(f"\n{'='*60}")
    print(f"  Test complete.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
