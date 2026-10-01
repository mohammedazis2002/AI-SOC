"""
Agentic Dispatcher — Sequential Lock-Step Multi-Worker
=======================================================
Bridges the Redis alert queues to the LangGraph AI agent pipeline.

Design constraints:
  - Each agent instance holds LangGraph state in-process memory and can only
    process ONE alert at a time. Sending two concurrent alerts to the same
    agent instance corrupts the state graph.
  - Solution: N worker coroutines, each owning a DEDICATED agent instance URL.
    Concurrency = number of running agent containers.

Worker behaviour per coroutine:
  1. Health-check its assigned agent instance.
  2. Pop one alert from priority_queue (ZSET) then standard_queue (list).
     Redis atomic ops ensure no two workers pop the same alert.
  3. Fetch full alert document from MongoDB alerts_processed.
  4. POST to /webhook/alert on its agent instance.
  5. Poll /status/{alert_id} every POLL_INTERVAL_SEC seconds.
  6. Release lock and loop once the agent reports completion (HTTP 200)
     or MAX_WAIT_TIME_SEC is exceeded (3 min = 2.5 min agent max + 30 s buffer).

Configuration (all via environment variables):
  AGENT_API_URLS        Comma-separated list of agent URLs, one per worker.
                        If fewer URLs than workers, workers share URLs round-robin.
                        Example: "http://agent-1:8000,http://agent-2:8000"
  AGENT_API_URL         Fallback single-URL alias (backward-compatible).
  DISPATCHER_WORKERS    Number of concurrent worker coroutines (default: 3).
  DISPATCHER_TIMEOUT_SEC  Per-alert timeout in seconds (default: 180 = 3 min).
  DISPATCHER_POLL_INTERVAL  Status poll frequency in seconds (default: 5).
  REDIS_HOST / REDIS_PORT / REDIS_PASSWORD
  MONGO_URI / MONGODB_DATABASE
"""

import os
import json
import logging
import asyncio
import httpx
from pymongo import MongoClient
import redis as redis_lib

from datetime import datetime

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("agent_dispatcher")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_raw_urls = os.environ.get("AGENT_API_URLS") or os.environ.get(
    "AGENT_API_URL", "http://soar-agent-api:8000"
)
AGENT_URLS = [u.strip() for u in _raw_urls.split(",") if u.strip()]

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")  # No default — must be set in env

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://mongodb:27017/")
MONGO_DATABASE = os.environ.get("MONGODB_DATABASE", "soar_db")

POLL_INTERVAL_SEC = int(os.environ.get("DISPATCHER_POLL_INTERVAL", "5"))
# Agent pipeline max is ~2.5 min. Adding 30 s buffer → 3 min hard timeout.
MAX_WAIT_TIME_SEC = int(os.environ.get("DISPATCHER_TIMEOUT_SEC", "180"))
# IMPORTANT: DISPATCHER_WORKERS must equal the number of agent container
# replicas. Each worker owns one agent instance (1:1 mapping) because the
# LangGraph pipeline holds per-alert state in-process memory — sending two
# concurrent alerts to the same instance corrupts the state graph.
# Range: [2, 8]. Default 5 (mid-range). Autoscaler sets this based on
# the attack forecaster output (scales up OR down every 10 min).
WORKER_COUNT = int(os.environ.get("DISPATCHER_WORKERS", "5"))


# ---------------------------------------------------------------------------
# Single worker coroutine
# ---------------------------------------------------------------------------
def make_serializable(doc: dict) -> dict:
    """Recursively convert non-JSON-serializable types in a MongoDB document."""
    result = {}
    for k, v in doc.items():
        if isinstance(v, datetime):
            result[k] = v.isoformat()
        elif isinstance(v, dict):
            result[k] = make_serializable(v)
        elif isinstance(v, list):
            result[k] = [
                (
                    make_serializable(i)
                    if isinstance(i, dict)
                    else i.isoformat() if isinstance(i, datetime) else i
                )
                for i in v
            ]
        else:
            result[k] = v
    return result


async def dispatch_worker(
    worker_id: int,
    agent_url: str,
    db,  # pymongo Database
    r,  # redis.Redis
) -> None:
    """
    Continuously dequeue one alert, hand it to the assigned agent instance,
    and wait for completion before picking up the next one.
    """
    logger.info(f"[Worker-{worker_id}] Started → agent: {agent_url}")

    async with httpx.AsyncClient() as client:
        while True:
            try:
                # ── 1. Health-check the agent ────────────────────────────────
                try:
                    health = await client.get(f"{agent_url}/health", timeout=5.0)
                    if health.status_code != 200:
                        logger.warning(
                            f"[Worker-{worker_id}] Agent unhealthy "
                            f"(HTTP {health.status_code}). Retrying in 10 s…"
                        )
                        await asyncio.sleep(10)
                        continue
                except Exception as e:
                    logger.warning(
                        f"[Worker-{worker_id}] Agent unreachable ({str(e)[:60]}). "
                        f"Waiting for recovery…"
                    )
                    await asyncio.sleep(10)
                    continue

                # ── 2. Dequeue one alert (priority first, then standard) ──────
                alert_id = None
                queue_label = None

                res = r.zpopmin("priority_queue", 1)
                if res:
                    alert_id = res[0][0]
                    queue_label = "priority_queue"
                else:
                    res = r.lpop("standard_queue")
                    if res:
                        alert_id = res
                        queue_label = "standard_queue"

                if not alert_id:
                    await asyncio.sleep(3)
                    continue

                logger.info(
                    f"[Worker-{worker_id}] Dequeued {alert_id} from {queue_label}"
                )

                # ── 3. Fetch full alert document from MongoDB ─────────────────
                alert_doc = db.alerts_processed.find_one({"alert_id": alert_id})
                if not alert_doc:
                    logger.error(
                        f"[Worker-{worker_id}] Alert {alert_id} not found in "
                        f"alerts_processed — dropping."
                    )
                    continue

                alert_doc.pop("_id", None)
                alert_doc = make_serializable(alert_doc)

                # ── 4. Forward to agent ───────────────────────────────────────
                payload = {
                    "alert_id": alert_id,
                    "alert": alert_doc,
                    "priority": "P1" if queue_label == "priority_queue" else "P3",
                }

                try:
                    post_res = await client.post(
                        f"{agent_url}/webhook/alert",
                        json=payload,
                        timeout=15.0,
                    )
                except Exception as e:
                    logger.error(
                        f"[Worker-{worker_id}] Failed to POST alert {alert_id} "
                        f"to agent: {e}. Dropping — alert already in MongoDB."
                    )
                    continue

                if post_res.status_code != 200:
                    logger.error(
                        f"[Worker-{worker_id}] Agent rejected {alert_id} "
                        f"(HTTP {post_res.status_code}): {post_res.text[:200]}"
                    )
                    continue

                logger.info(
                    f"[Worker-{worker_id}] {alert_id} dispatched — "
                    f"holding until agent completes (max {MAX_WAIT_TIME_SEC} s)…"
                )

                # ── 5. Poll for completion ────────────────────────────────────
                elapsed = 0
                completed = False

                while elapsed < MAX_WAIT_TIME_SEC:
                    await asyncio.sleep(POLL_INTERVAL_SEC)
                    elapsed += POLL_INTERVAL_SEC

                    try:
                        status_res = await client.get(
                            f"{agent_url}/status/{alert_id}",
                            timeout=5.0,
                        )
                        if status_res.status_code == 200:
                            decision = status_res.json().get("decision", "UNKNOWN")
                            logger.info(
                                f"[Worker-{worker_id}] ✅ {alert_id} complete "
                                f"— decision: {decision} ({elapsed} s)"
                            )
                            completed = True
                            break
                        elif status_res.status_code == 404:
                            # Still processing — heartbeat every 30 s
                            if elapsed % 30 == 0:
                                logger.info(
                                    f"[Worker-{worker_id}] … still reasoning "
                                    f"over {alert_id} ({elapsed} s / {MAX_WAIT_TIME_SEC} s)"
                                )
                        else:
                            logger.warning(
                                f"[Worker-{worker_id}] Unexpected status "
                                f"HTTP {status_res.status_code} for {alert_id}"
                            )
                    except Exception as pe:
                        logger.warning(
                            f"[Worker-{worker_id}] Status poll failed: {str(pe)[:60]}"
                        )

                if not completed:
                    logger.error(
                        f"[Worker-{worker_id}] ⚠️  Alert {alert_id} timed out "
                        f"after {MAX_WAIT_TIME_SEC} s — agent may be hung. "
                        f"Releasing lock and continuing."
                    )

            except Exception as loop_err:
                logger.error(
                    f"[Worker-{worker_id}] Unhandled loop error: {loop_err}",
                    exc_info=True,
                )
                await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# Startup: connect shared resources, launch N workers
# ---------------------------------------------------------------------------


async def start_dispatcher() -> None:
    logger.info(
        f"Dispatcher starting — {WORKER_COUNT} worker(s), "
        f"{len(AGENT_URLS)} agent URL(s), "
        f"timeout {MAX_WAIT_TIME_SEC} s/alert"
    )

    # ── MongoDB ──────────────────────────────────────────────────────────────
    try:
        mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        mongo_client.admin.command("ping")
        db = mongo_client[MONGO_DATABASE]
        logger.info(f"✅ MongoDB connected: {MONGO_DATABASE}")
    except Exception as e:
        logger.fatal(f"❌ MongoDB connection failed: {e}")
        return

    # ── Redis ────────────────────────────────────────────────────────────────
    try:
        r = redis_lib.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,  # None → no auth (local dev)
            db=0,
            decode_responses=True,
        )
        r.ping()
        logger.info(f"✅ Redis connected: {REDIS_HOST}:{REDIS_PORT}")
    except Exception as e:
        logger.fatal(f"❌ Redis connection failed: {e}")
        return

    # ── Launch N concurrent workers ──────────────────────────────────────────
    # Each worker gets its own dedicated agent URL (round-robin if fewer URLs
    # than workers, e.g. Docker Compose replicas behind a single hostname).
    tasks = [
        dispatch_worker(
            worker_id=i,
            agent_url=AGENT_URLS[i % len(AGENT_URLS)],
            db=db,
            r=r,
        )
        for i in range(WORKER_COUNT)
    ]

    logger.info(
        f"Launching workers: "
        + ", ".join(
            f"Worker-{i}→{AGENT_URLS[i % len(AGENT_URLS)]}" for i in range(WORKER_COUNT)
        )
    )

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(start_dispatcher())
