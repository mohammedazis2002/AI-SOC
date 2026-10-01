"""
Correlation Engine – Background Correlator (Path C)
=====================================================
Async deep correlation with 6 weighted layers.
Runs in background worker pool; never blocks the alert pipeline.

Architecture:
  - asyncio.Queue (maxsize=10 000) feeds 5 parallel workers
  - Each worker calls deep_correlate() → 6 layers in parallel
  - Per-layer asyncio.wait_for() timeouts prevent stalls
  - Circuit breaker on ML microservice calls (Layers 5 & 6)
  - Failed alerts → Redis DLQ stream (corr:dlq), retried once after 60 s
  - If confidence > threshold → IncidentTracker creates/updates incident

Layer weights (must sum to 1.0):
  Temporal   0.15
  Entity     0.20
  Pattern    0.30
  Graph      0.15
  Behavioral 0.10
  ML         0.10

On ML circuit-breaker open: ML weight redistributed to Pattern (0.30 → 0.40).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pymongo import MongoClient

import redis.asyncio as aioredis

from .incident_tracker import IncidentTracker
from .models import AlertRef, CorrelationResult, CorrelationType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TEMPORAL_HOURS          = int(os.getenv("CORRELATION_TEMPORAL_HOURS",  "24"))
ENTITY_DAYS             = int(os.getenv("CORRELATION_ENTITY_DAYS",     "7"))
PATTERN_DAYS            = int(os.getenv("CORRELATION_PATTERN_DAYS",    "30"))
CONFIDENCE_THRESHOLD    = float(os.getenv("CORRELATION_CONFIDENCE_THRESHOLD", "0.7"))
BACKGROUND_WORKERS      = int(os.getenv("CORRELATION_BACKGROUND_WORKERS", "5"))
QUEUE_MAX_SIZE          = int(os.getenv("CORR_QUEUE_MAX_SIZE", "10000"))
DLQ_RETRY_DELAY_S       = int(os.getenv("CORR_DLQ_RETRY_DELAY_S", "60"))

ANOMALY_URL   = os.getenv("ANOMALY_DETECTION_URL",   "http://anomaly-detection:5001")
ATTACK_STG_URL = os.getenv("ATTACK_STAGE_URL",        "http://attack-stage-predictor:5002")
ML_TIMEOUT_S  = int(os.getenv("CORR_ML_TIMEOUT_S", "10"))

# Layer timeouts (seconds)
_LAYER_TIMEOUTS: Dict[str, int] = {
    "temporal":   int(os.getenv("CORR_TIMEOUT_TEMPORAL",   "10")),
    "entity":     int(os.getenv("CORR_TIMEOUT_ENTITY",     "15")),
    "pattern":    int(os.getenv("CORR_TIMEOUT_PATTERN",    "20")),
    "graph":      int(os.getenv("CORR_TIMEOUT_GRAPH",      "30")),
    "behavioral": int(os.getenv("CORR_TIMEOUT_BEHAVIORAL", "15")),
    "ml":         int(os.getenv("CORR_TIMEOUT_ML",         "10")),
}

_BASE_WEIGHTS: Dict[str, float] = {
    "temporal": 0.15, "entity": 0.20, "pattern": 0.30,
    "graph": 0.15, "behavioral": 0.10, "ml": 0.10,
}

# Simple circuit breaker config
_CB_FAILURE_THRESHOLD = 3
_CB_RECOVERY_TIMEOUT_S = 30


# ---------------------------------------------------------------------------
# Minimal circuit breaker
# ---------------------------------------------------------------------------

class _CircuitBreaker:
    def __init__(self, name: str) -> None:
        self.name             = name
        self._failures        = 0
        self._open_since: Optional[float] = None

    @property
    def is_open(self) -> bool:
        if self._open_since is None:
            return False
        if time.monotonic() - self._open_since > _CB_RECOVERY_TIMEOUT_S:
            # Half-open: allow one attempt
            self._open_since = None
            self._failures   = 0
            return False
        return True

    def record_success(self) -> None:
        self._failures   = 0
        self._open_since = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= _CB_FAILURE_THRESHOLD:
            if self._open_since is None:
                logger.warning(f"CircuitBreaker[{self.name}] OPEN after {self._failures} failures")
                self._open_since = time.monotonic()


# ---------------------------------------------------------------------------
# BackgroundCorrelationEngine
# ---------------------------------------------------------------------------

class BackgroundCorrelationEngine:
    """
    Deep correlation engine — runs fully asynchronously.
    Call start() to launch workers; call enqueue(alert) to submit work.
    """

    def __init__(
        self,
        incident_tracker: Optional[IncidentTracker] = None,
        db_client: Optional[Any] = None,
        redis_client: Optional[aioredis.Redis] = None,
    ) -> None:
        self._incident_tracker = incident_tracker
        self._db               = db_client            # MongoDB db object
        self._redis            = redis_client
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
        self._overflow_count   = 0
        self._workers_started  = False
        self._http             = httpx.AsyncClient(timeout=ML_TIMEOUT_S + 2)
        self._cb_anomaly       = _CircuitBreaker("anomaly_detection")
        self._cb_attack_stage  = _CircuitBreaker("attack_stage")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Launch background worker tasks. Call once at app startup."""
        if self._workers_started:
            return
        for i in range(BACKGROUND_WORKERS):
            asyncio.ensure_future(self._worker(i))
        self._workers_started = True
        logger.info(f"BackgroundCorrelator: {BACKGROUND_WORKERS} workers started")

    async def enqueue(self, alert: Dict[str, Any]) -> bool:
        """
        Submit an alert for deep correlation.
        Returns False if the queue is full (overflow logged, alert dropped from corr only).
        """
        try:
            self._queue.put_nowait(alert)
            return True
        except asyncio.QueueFull:
            self._overflow_count += 1
            logger.warning(
                f"BackgroundCorrelator: queue full (overflow #{self._overflow_count}). "
                f"Alert {alert.get('alert_id')} dropped from deep correlation."
            )
            return False

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    @property
    def overflow_count(self) -> int:
        return self._overflow_count

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    async def _worker(self, worker_id: int) -> None:
        logger.info(f"BackgroundCorrelator worker-{worker_id} started")
        while True:
            alert: Optional[Dict[str, Any]] = None
            try:
                alert = await self._queue.get()
                await self._process(alert)
            except asyncio.CancelledError:
                logger.info(f"BackgroundCorrelator worker-{worker_id} cancelled")
                break
            except Exception as exc:
                logger.error(
                    f"BackgroundCorrelator worker-{worker_id} error: {exc}",
                    exc_info=True,
                )
                if alert is not None:
                    await self._send_to_dlq(alert, str(exc))
            finally:
                try:
                    self._queue.task_done()
                except ValueError:
                    pass  # task_done called on empty queue — safe to ignore

    async def _process(self, alert: Dict[str, Any]) -> None:
        alert_id = alert.get("alert_id", "?")
        logger.debug(f"BackgroundCorrelator processing alert {alert_id}")

        result = await self.deep_correlate(alert)

        if result and result.get("correlated"):
            await self._handle_correlation_found(alert, result)

    # ------------------------------------------------------------------
    # Deep correlation (6 layers, parallel, each with timeout)
    # ------------------------------------------------------------------

    async def deep_correlate(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run all 6 correlation layers; return a scored result dict."""
        ref = AlertRef.from_alert(alert)

        # Run all 6 layers concurrently, each with its own timeout guard
        results = await asyncio.gather(
            self._timed("temporal",   self._layer_temporal(ref)),
            self._timed("entity",     self._layer_entity(ref)),
            self._timed("pattern",    self._layer_pattern(ref)),
            self._timed("graph",      self._layer_graph(ref)),
            self._timed("behavioral", self._layer_behavioral(ref)),
            self._timed("ml",         self._layer_ml(alert)),
            return_exceptions=False,
        )

        temporal_score, temporal_alerts = results[0]
        entity_score,   entity_alerts = results[1]
        pattern_score,  pattern_alerts, pattern_name = results[2]
        graph_score,    graph_alerts = results[3]
        behav_score,    behav_alerts = results[4]
        ml_score,       ml_degraded = results[5]

        # Unpack pattern tuple (score, alerts, name)  — others are (score, list)
        # Actually gather returns values as positional — restructure via _timed wrappers
        # (see _timed return structure below)

        # Build weighted confidence
        weights = dict(_BASE_WEIGHTS)
        if ml_degraded:
            weights["ml"]     = 0.0
            weights["pattern"] += 0.10  # redistribute ML weight to pattern

        # Normalise so weights always sum to 1
        total_w = sum(weights.values())
        if total_w > 0:
            weights = {k: v / total_w for k, v in weights.items()}

        confidence = (
            weights["temporal"]   * temporal_score  +
            weights["entity"]     * entity_score    +
            weights["pattern"]    * pattern_score   +
            weights["graph"]      * graph_score     +
            weights["behavioral"] * behav_score     +
            weights["ml"]         * ml_score
        )

        all_related = list({
            *temporal_alerts, *entity_alerts, *pattern_alerts,
            *graph_alerts, *behav_alerts,
        })

        if confidence < CONFIDENCE_THRESHOLD:
            logger.debug(
                f"Alert {ref.alert_id}: deep corr score {confidence:.2f} < threshold {CONFIDENCE_THRESHOLD}"
            )
            return None

        return {
            "correlated":     True,
            "confidence":     confidence,
            "related_alerts": all_related,
            "attack_pattern": pattern_name,
            "ml_degraded":    ml_degraded,
            "narrative":      self._build_narrative(ref, confidence, pattern_name, all_related),
        }

    # ------------------------------------------------------------------
    # Helper: timeout wrapper
    # ------------------------------------------------------------------

    async def _timed(self, layer: str, coro) -> tuple:
        """Wrap a layer coroutine with a timeout; return (score, *extras) on timeout."""
        timeout = _LAYER_TIMEOUTS.get(layer, 15)
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"BackgroundCorrelator: layer '{layer}' timed out after {timeout}s")
            # Return a safe zero-score tuple that matches the layer's return shape
            if layer == "pattern":
                return 0.0, [], None
            if layer == "ml":
                return 0.0, True   # (score, degraded=True)
            return 0.0, []
        except Exception as exc:
            logger.error(f"BackgroundCorrelator: layer '{layer}' error: {exc}")
            if layer == "pattern":
                return 0.0, [], None
            if layer == "ml":
                return 0.0, True
            return 0.0, []

    # ------------------------------------------------------------------
    # Layer 1: Temporal (24-hour window)
    # ------------------------------------------------------------------

    async def _layer_temporal(self, ref: AlertRef) -> Tuple[float, List[str]]:
        if self._db is None:
            return 0.0, []
        cutoff = datetime.utcnow() - timedelta(hours=TEMPORAL_HOURS)
        filters: Dict[str, Any] = {
            "processed_at": {"$gte": cutoff},
            "alert_id":     {"$ne": ref.alert_id},
        }
        if ref.user:
            filters["$or"] = [{"user": ref.user}, {"actor.user.name": ref.user}]
        elif ref.source_ip:
            filters["$or"] = [{"source_ip": ref.source_ip}, {"src_endpoint.ip": ref.source_ip}]
        else:
            return 0.0, []

        docs = list(self._db.alerts.find(filters, {"alert_id": 1}).limit(20))
        ids  = [d["alert_id"] for d in docs if d.get("alert_id")]
        score = min(len(ids) / 5.0, 1.0)  # 5+ alerts in window → full score for this layer
        return score, ids

    # ------------------------------------------------------------------
    # Layer 2: Entity-based (7-day window)
    # ------------------------------------------------------------------

    async def _layer_entity(self, ref: AlertRef) -> Tuple[float, List[str]]:
        if self._db is None:
            return 0.0, []
        cutoff = datetime.utcnow() - timedelta(days=ENTITY_DAYS)
        matches: List[str] = []

        # Build entity queries
        entity_filters = []
        if ref.user:
            entity_filters.append({"user": ref.user})
            entity_filters.append({"actor.user.name": ref.user})
        if ref.source_ip:
            entity_filters.append({"source_ip": ref.source_ip})
            entity_filters.append({"src_endpoint.ip": ref.source_ip})

        if not entity_filters:
            return 0.0, []

        docs = list(self._db.alerts.find(
            {"$or": entity_filters, "processed_at": {"$gte": cutoff}, "alert_id": {"$ne": ref.alert_id}},
            {"alert_id": 1},
        ).limit(30))
        matches = [d["alert_id"] for d in docs if d.get("alert_id")]
        score   = min(len(matches) / 10.0, 1.0)
        return score, matches

    # ------------------------------------------------------------------
    # Layer 3: Pattern matching (30-day MITRE chain window)
    # ------------------------------------------------------------------

    # Known APT kill-chain sequences: (trigger_technique, precursor_technique, name, max_days)
    _MITRE_CHAINS = [
        ("T1056.001", "T1566", "phishing_credential_theft",  30),
        ("T1486",     "T1059.001", "ps_ransomware",          7),
        ("T1078",     "T1566", "phishing_account_takeover",  30),
        ("T1041",     "T1105", "download_then_exfil",        14),
        ("T1003",     "T1078", "account_access_credential_dump", 30),
        ("T1059.001", "T1566", "phishing_to_powershell",     30),
    ]

    async def _layer_pattern(self, ref: AlertRef) -> Tuple[float, List[str], Optional[str]]:
        if self._db is None or not ref.mitre_technique:
            return 0.0, [], None

        technique = (ref.mitre_technique or "").upper()
        cutoff    = datetime.utcnow() - timedelta(days=PATTERN_DAYS)

        for trigger, precursor, name, max_days in self._MITRE_CHAINS:
            if not technique.startswith(trigger):
                continue
            window_cutoff = datetime.utcnow() - timedelta(days=max_days)
            actual_cutoff = max(cutoff, window_cutoff)

            # entity filter
            entity_f: List[Dict] = []
            if ref.user:
                entity_f += [{"user": ref.user}, {"actor.user.name": ref.user}]
            if ref.source_ip:
                entity_f += [{"source_ip": ref.source_ip}]

            if not entity_f:
                continue

            docs = list(self._db.alerts.find({
                "$or": entity_f,
                "processed_at": {"$gte": actual_cutoff},
                "alert_id": {"$ne": ref.alert_id},
                "$or": [
                    {"mitre_technique": {"$regex": f"^{precursor}", "$options": "i"}},
                    {"enrichments.mitre.technique_id": {"$regex": f"^{precursor}", "$options": "i"}},
                ],
            }, {"alert_id": 1}).limit(10))

            ids = [d["alert_id"] for d in docs if d.get("alert_id")]
            if ids:
                logger.info(
                    f"BackgroundCorrelator: pattern '{name}' matched for alert "
                    f"{ref.alert_id} (precursors: {ids})"
                )
                return 0.9, ids, name

        return 0.0, [], None

    # ------------------------------------------------------------------
    # Layer 4: Graph analysis (no time bound)
    # ------------------------------------------------------------------

    async def _layer_graph(self, ref: AlertRef) -> Tuple[float, List[str]]:
        """
        Build a 2-hop entity graph to detect lateral movement / pivoting.
        Node = entity (user, IP, hostname); Edge = co-occurrence in the same alert.
        """
        if self._db is None:
            return 0.0, []

        # Gather all alerts sharing any entity with this alert
        entity_f: List[Dict] = []
        if ref.user:
            entity_f += [{"user": ref.user}, {"actor.user.name": ref.user}]
        if ref.source_ip:
            entity_f += [{"source_ip": ref.source_ip}, {"src_endpoint.ip": ref.source_ip}]

        if not entity_f:
            return 0.0, []

        hop1 = list(self._db.alerts.find(
            {"$or": entity_f, "alert_id": {"$ne": ref.alert_id}},
            {"alert_id": 1, "user": 1, "source_ip": 1, "src_endpoint": 1, "actor": 1},
        ).limit(50))

        if not hop1:
            return 0.0, []

        # Collect entities from hop-1 neighbours
        hop1_entities: List[Dict] = []
        for doc in hop1:
            u  = doc.get("user") or (doc.get("actor") or {}).get("user", {}).get("name")
            ip = doc.get("source_ip") or (doc.get("src_endpoint") or {}).get("ip")
            if u:  hop1_entities.append({"user": u})
            if ip: hop1_entities.append({"source_ip": ip})

        if not hop1_entities:
            return min(len(hop1) / 10.0, 0.6), [d["alert_id"] for d in hop1 if d.get("alert_id")]

        # Hop-2: alerts connecting to hop-1 entities (lateral movement indicator)
        hop2 = list(self._db.alerts.find(
            {"$or": hop1_entities, "alert_id": {"$nin": [d["alert_id"] for d in hop1] + [ref.alert_id]}},
            {"alert_id": 1},
        ).limit(30))

        all_ids = [d["alert_id"] for d in hop1 + hop2 if d.get("alert_id")]
        score   = min(len(all_ids) / 15.0, 1.0)
        return score, all_ids

    # ------------------------------------------------------------------
    # Layer 5: Behavioral (per-user, no time bound)
    # ------------------------------------------------------------------

    async def _layer_behavioral(self, ref: AlertRef) -> Tuple[float, List[str]]:
        """
        Compare current alert severity/technique against the historical user baseline.
        Alerts dramatically outside the user's normal profile → high score.
        """
        if self._db is None or not ref.user:
            return 0.0, []

        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        current_sev = sev_rank.get((ref.severity or "").lower(), 2)

        past_alerts = list(self._db.alerts.find(
            {"$or": [{"user": ref.user}, {"actor.user.name": ref.user}],
             "alert_id": {"$ne": ref.alert_id}},
            {"severity": 1, "alert_id": 1},
        ).limit(100))

        if not past_alerts:
            return 0.0, []

        past_sevs = [sev_rank.get(str(d.get("severity", "")).lower(), 2) for d in past_alerts]
        avg_sev   = sum(past_sevs) / len(past_sevs)
        deviation = abs(current_sev - avg_sev) / 3.0  # max deviation = 3 levels

        related   = [d["alert_id"] for d in past_alerts if d.get("alert_id")]
        return min(deviation, 1.0), related[:20]

    # ------------------------------------------------------------------
    # Layer 6: ML (calls anomaly_detection + attack_stage microservices)
    # ------------------------------------------------------------------

    async def _layer_ml(self, alert: Dict[str, Any]) -> Tuple[float, bool]:
        """
        Query existing anomaly_detection and attack_stage microservices.
        Returns (score, degraded). Uses circuit breakers to avoid cascading failures.
        """
        scores: List[float] = []
        degraded = False

        # --- Anomaly Detection ---
        if not self._cb_anomaly.is_open:
            try:
                resp = await self._http.post(
                    f"{ANOMALY_URL}/detect",
                    content=json.dumps({"alert": alert}, default=str),
                    headers={"Content-Type": "application/json"},
                    timeout=ML_TIMEOUT_S,
                )
                resp.raise_for_status()
                data = resp.json()
                scores.append(float(data.get("anomaly_score", 0.0)))
                self._cb_anomaly.record_success()
            except Exception as exc:
                logger.warning(f"ML layer: anomaly_detection call failed: {exc}")
                self._cb_anomaly.record_failure()
                degraded = True
        else:
            logger.debug("ML layer: anomaly_detection circuit OPEN, skipping")
            degraded = True

        # --- Attack Stage ---
        if not self._cb_attack_stage.is_open:
            try:
                resp = await self._http.post(
                    f"{ATTACK_STG_URL}/predict",
                    content=json.dumps({"alert": alert}, default=str),
                    headers={"Content-Type": "application/json"},
                    timeout=ML_TIMEOUT_S,
                )
                resp.raise_for_status()
                data  = resp.json()
                stage = data.get("attack_stage", "unknown")
                # Translate stage to a suspicion score
                stage_scores = {
                    "reconnaissance": 0.5, "weaponization": 0.6,
                    "delivery": 0.7, "exploitation": 0.85,
                    "installation": 0.9, "command_control": 0.95,
                    "actions_on_objective": 1.0,
                }
                scores.append(stage_scores.get(stage, 0.4))
                self._cb_attack_stage.record_success()
            except Exception as exc:
                logger.warning(f"ML layer: attack_stage call failed: {exc}")
                self._cb_attack_stage.record_failure()
                degraded = True
        else:
            logger.debug("ML layer: attack_stage circuit OPEN, skipping")
            degraded = True

        score = sum(scores) / len(scores) if scores else 0.0
        return score, degraded

    # ------------------------------------------------------------------
    # Incident handling (retroactive)
    # ------------------------------------------------------------------

    async def _handle_correlation_found(
        self,
        trigger_alert: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        if not self._incident_tracker:
            return

        related_ids = result.get("related_alerts", [])
        all_ids     = list({*related_ids, trigger_alert.get("alert_id", "")})

        # Build AlertRef objects for all linked alerts
        alert_refs = [AlertRef.from_alert(trigger_alert)]
        if related_ids and self._db is not None:
            docs = list(self._db.alerts.find(
                {"alert_id": {"$in": related_ids}},
                {"alert_id": 1, "user": 1, "source_ip": 1, "severity": 1,
                 "enrichments": 1, "mitre_technique": 1, "actor": 1, "src_endpoint": 1},
            ))
            alert_refs += [AlertRef.from_alert(d) for d in docs]

        # Build CorrelationResult
        from .models import CorrelationType
        corr_result = CorrelationResult(
            correlation_type=CorrelationType.MITRE_CHAIN if result.get("attack_pattern") else CorrelationType.TEMPORAL_CLUSTER,
            confidence=result["confidence"],
            related_alert_ids=all_ids,
            attack_pattern=result.get("attack_pattern"),
            narrative=result.get("narrative"),
            layer="deep",
            degraded=result.get("ml_degraded", False),
        )

        # Check if incident already exists
        existing = await self._incident_tracker.find_incident_by_alerts(all_ids)
        if existing:
            await self._incident_tracker.add_alert_to_incident(
                existing["incident_id"],
                alert_refs[0],
                [corr_result],
            )
            logger.info(
                f"BackgroundCorrelator: alert {trigger_alert.get('alert_id')} "
                f"added to existing incident {existing['incident_id']}"
            )
        else:
            await self._incident_tracker.create_incident(
                alert_refs,
                [corr_result],
                narrative=result.get("narrative"),
            )

    # ------------------------------------------------------------------
    # DLQ
    # ------------------------------------------------------------------

    async def _send_to_dlq(self, alert: Dict[str, Any], error: str) -> None:
        if not self._redis:
            return
        try:
            await self._redis.xadd(
                "corr:dlq",
                {
                    "alert_id":  str(alert.get("alert_id", "")),
                    "error":     error[:512],
                    "payload":   json.dumps(alert, default=str)[:8192],
                    "ts":        datetime.utcnow().isoformat(),
                },
            )
        except Exception as exc:
            logger.warning(f"BackgroundCorrelator: DLQ write failed: {exc}")

    # ------------------------------------------------------------------
    # Narrative builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_narrative(
        ref: AlertRef,
        confidence: float,
        pattern: Optional[str],
        related_ids: List[str],
    ) -> str:
        parts = [
            f"Deep correlation detected for alert {ref.alert_id}.",
            f"Combined confidence: {confidence:.0%}.",
        ]
        if pattern:
            parts.append(f"Matched attack pattern: {pattern}.")
        if related_ids:
            parts.append(f"Linked to {len(related_ids)} earlier alert(s).")
        return " ".join(parts)
