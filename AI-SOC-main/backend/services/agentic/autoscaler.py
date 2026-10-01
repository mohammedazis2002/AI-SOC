"""
Agentic Autoscaler
==================
Queries the Attack Forecaster every SCALE_CHECK_INTERVAL_MIN minutes,
computes the required number of agent container replicas, and scales
both the Docker Compose service and the dispatcher worker count.

Scaling logic
-------------
  predicted_volume  = alerts forecast for the next hour (from forecaster)
  avg_process_sec   = measured/estimated average processing time per alert
  required_workers  = ceil(predicted_volume * avg_process_sec / 3600)
  required_workers  = clamp(required_workers, MIN_WORKERS, MAX_WORKERS)

Why this formula:
  In one hour there are 3600 seconds available per worker.
  Each alert occupies a worker for avg_process_sec seconds.
  So one worker handles 3600 / avg_process_sec alerts/hour.
  To handle predicted_volume alerts/hour you need the above workers.

Example (14 K/day → 583/hr, avg 120 s/alert):
  required = ceil(583 * 120 / 3600) = ceil(19.4) = clamped to MAX_WORKERS=8
  At night with forecast of 50/hr: ceil(50*120/3600) = 2 = MIN_WORKERS

Why MAX_WORKERS = 8
-------------------
Agent containers are lightweight Python/FastAPI processes (~200-300 MB RAM,
no GPU usage). They call vLLM over HTTP — they don’t hold LLM weights.

The bottleneck is vLLM concurrent-request throughput on the single A100 80 GB:
  - 70B INT4 loaded (≈40 GB) + 8B INT4 (≈5 GB) = ≈45 GB total
  - vLLM continuous batching interleaves multiple sequences on the GPU.
    Agent steps are sequential (normalise → triage → investigate → remediate)
    so not all agents are making LLM calls at the exact same millisecond.
    This natural staggering allows 8 concurrent agents to share the GPU
    efficiently without saturating it.
  - Beyond 8, KV-cache pressure on the 70B model starts causing evictions,
    increasing per-request latency. Hard-cap at 8.

Scaling direction
-----------------
Bidirectional: scale UP when forecast predicts higher load; scale DOWN
during low-load windows (e.g. overnight) to free CPU/RAM for the rest
of the stack. Start at 5 (middle of the 2–8 range) on boot.

Configuration (all env vars):
  FORECASTER_URL          URL of attack forecaster service
  SCALE_CHECK_INTERVAL_MIN  How often to re-evaluate scale (default: 10)
  AVG_PROCESS_SEC         Average seconds per alert end-to-end (default: 120)
  MIN_WORKERS             Floor — never scale below this (default: 3)
  MAX_WORKERS             Hard ceiling from vLLM throughput (default: 5)
  DEPLOYMENT_MODE         'compose' or 'swarm' (default: compose)
  COMPOSE_PROJECT_NAME    Docker Compose project name (default: soar-platform)
  AGENT_SERVICE_NAME      Service name in compose/swarm (default: soar-agent-api)
  DISPATCHER_SERVICE_NAME Dispatcher service name (default: agent-dispatcher)
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import subprocess
from typing import Optional

import httpx

logger = logging.getLogger("autoscaler")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
FORECASTER_URL           = os.environ.get("FORECASTER_URL", "http://attack-forecaster:5005")
SCALE_CHECK_INTERVAL_MIN = int(os.environ.get("SCALE_CHECK_INTERVAL_MIN", "10"))
# Avg processing time per alert through the full multi-agent pipeline.
# Max timeout is 180 s (3 min); realistic average across severities is ~120 s (2 min).
AVG_PROCESS_SEC          = int(os.environ.get("AVG_PROCESS_SEC", "120"))

# Start at MAX_WORKERS (full capacity). Autoscaler will scale down if the
# forecaster predicts low load; never scale up beyond MAX_WORKERS.
MIN_WORKERS              = int(os.environ.get("MIN_WORKERS", "2"))
# Cap of 8 set by vLLM KV-cache pressure on the single A100 80 GB.
# Agents are CPU-only; the GPU is the shared bottleneck.
MAX_WORKERS              = int(os.environ.get("MAX_WORKERS", "8"))
# Default start: 5 (middle of range). Autoscaler adjusts up/down from here.
DEFAULT_WORKERS          = int(os.environ.get("DEFAULT_WORKERS", "5"))

DEPLOYMENT_MODE          = os.environ.get("DEPLOYMENT_MODE", "compose")   # 'compose' | 'swarm'
COMPOSE_PROJECT_NAME     = os.environ.get("COMPOSE_PROJECT_NAME", "soar-platform")
AGENT_SERVICE_NAME       = os.environ.get("AGENT_SERVICE_NAME", "soar-agent-api")
DISPATCHER_SERVICE_NAME  = os.environ.get("DISPATCHER_SERVICE_NAME", "agent-dispatcher")


# ---------------------------------------------------------------------------
# Core scaling logic
# ---------------------------------------------------------------------------

def compute_required_workers(predicted_alerts_per_hour: float) -> int:
    """
    Returns the number of agent instances needed to process the forecasted
    alert volume in real-time without falling behind.

    Formula:
        workers = ceil(volume_per_hour * avg_process_sec / 3600)

    Clamped between MIN_WORKERS and MAX_WORKERS.
    """
    if predicted_alerts_per_hour <= 0:
        return MIN_WORKERS

    raw = math.ceil(predicted_alerts_per_hour * AVG_PROCESS_SEC / 3600)
    workers = max(MIN_WORKERS, min(raw, MAX_WORKERS))

    logger.info(
        f"Forecast: {predicted_alerts_per_hour:.0f} alerts/hr  "
        f"× {AVG_PROCESS_SEC}s avg  "
        f"→ raw={raw}  clamped={workers} workers"
    )
    return workers


# ---------------------------------------------------------------------------
# Forecaster query
# ---------------------------------------------------------------------------

async def fetch_forecast(client: httpx.AsyncClient) -> Optional[float]:
    """
    Ask the Attack Forecaster for the predicted alert volume in the next hour.
    Returns alerts/hour, or None on failure.
    """
    try:
        resp = await client.get(f"{FORECASTER_URL}/forecast/next_hour", timeout=10.0)
        resp.raise_for_status()
        data = resp.json()

        # Try common response shapes from the forecaster service
        volume = (
            data.get("predicted_count")        # primary field
            or data.get("forecast")
            or data.get("alerts_per_hour")
            or data.get("prediction")
        )
        if volume is not None:
            return float(volume)

        logger.warning(f"Forecaster response missing expected field: {data}")
        return None

    except Exception as exc:
        logger.warning(f"Forecaster unreachable or error: {exc} — keeping current scale")
        return None


# ---------------------------------------------------------------------------
# Docker scaling backends
# ---------------------------------------------------------------------------

def scale_compose(service: str, replicas: int) -> bool:
    """Scale a Docker Compose service to `replicas` instances."""
    try:
        result = subprocess.run(
            [
                "docker", "compose",
                "-p", COMPOSE_PROJECT_NAME,
                "up", "--scale", f"{service}={replicas}",
                "-d", "--no-recreate",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            logger.error(f"docker compose scale failed: {result.stderr[:300]}")
            return False
        logger.info(f"Scaled {service} → {replicas} replica(s)")
        return True
    except Exception as exc:
        logger.error(f"Scale error: {exc}")
        return False


def scale_swarm(service: str, replicas: int) -> bool:
    """Scale a Docker Swarm service to `replicas` instances."""
    try:
        import docker
        client = docker.from_env()
        svc = client.services.get(service)
        svc.scale(replicas)
        logger.info(f"Swarm: scaled {service} → {replicas} replica(s)")
        return True
    except Exception as exc:
        logger.error(f"Swarm scale error: {exc}")
        return False


def apply_scale(desired: int, current: int) -> bool:
    """Apply scaling only if the desired count differs from current."""
    if desired == current:
        logger.info(f"Scale unchanged at {current} worker(s) — nothing to do")
        return True

    logger.info(f"Scaling {AGENT_SERVICE_NAME}: {current} → {desired}")

    if DEPLOYMENT_MODE == "swarm":
        ok_agent = scale_swarm(AGENT_SERVICE_NAME, desired)
        # Also scale the dispatcher so DISPATCHER_WORKERS matches
        ok_disp  = scale_swarm(DISPATCHER_SERVICE_NAME, desired)
    else:
        ok_agent = scale_compose(AGENT_SERVICE_NAME, desired)
        ok_disp  = scale_compose(DISPATCHER_SERVICE_NAME, desired)

    return ok_agent and ok_disp


# ---------------------------------------------------------------------------
# Main autoscaler loop
# ---------------------------------------------------------------------------

async def run_autoscaler() -> None:
    logger.info(
        f"Autoscaler started — "
        f"check every {SCALE_CHECK_INTERVAL_MIN} min, "
        f"AVG_PROCESS_SEC={AVG_PROCESS_SEC}s, "
        f"workers [{MIN_WORKERS}–{MAX_WORKERS}]"
    )

    # Boot at DEFAULT_WORKERS (5). Autoscaler adjusts up or down from here
    # based on the forecaster output, staying within [MIN_WORKERS, MAX_WORKERS].
    current_workers = DEFAULT_WORKERS
    apply_scale(current_workers, 0)  # ensure containers are running at boot
    interval_sec    = SCALE_CHECK_INTERVAL_MIN * 60

    async with httpx.AsyncClient() as client:
        while True:
            try:
                predicted = await fetch_forecast(client)

                if predicted is not None:
                    desired = compute_required_workers(predicted)
                    apply_scale(desired, current_workers)
                    current_workers = desired
                else:
                    logger.info(
                        f"No forecast available — "
                        f"holding at {current_workers} worker(s)"
                    )

            except Exception as exc:
                logger.error(f"Autoscaler loop error: {exc}", exc_info=True)

            await asyncio.sleep(interval_sec)


if __name__ == "__main__":
    asyncio.run(run_autoscaler())
