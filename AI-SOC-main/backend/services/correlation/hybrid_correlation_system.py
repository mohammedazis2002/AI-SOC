"""
Correlation Engine – Hybrid Correlation System
================================================
Top-level orchestrator that combines all three paths:

  Path A: Immediate processing (done by AlertProcessor – NOT handled here)
  Path B: Quick correlation   – Redis, <5 s, runs await-ed
  Path C: Deep correlation    – Background asyncio workers, non-blocking

Usage (called from AlertProcessor.process_alert):
    result = await correlation_system.handle_alert(alert)
    alert['correlation'] = result.model_dump()

Graceful degradation:
  - Redis offline → quick correlator returns []
  - Background queue full → deep correlation dropped (logged)
  - Incident tracker unavailable → correlations still returned to caller
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from pymongo import MongoClient

from .background_correlator import BackgroundCorrelationEngine
from .incident_tracker import IncidentTracker
from .models import CorrelationHandleResult, CorrelationResult
from .quick_correlator import QuickCorrelationEngine

logger = logging.getLogger(__name__)

QUICK_CONFIDENCE_THRESHOLD = float(os.getenv("CORRELATION_QUICK_CONFIDENCE_THRESHOLD", "0.8"))


class HybridCorrelationSystem:
    """
    Singleton-friendly top-level orchestrator.
    Call start() once at app startup (launches background workers).
    """

    def __init__(
        self,
        db_client: Optional[Any] = None,
        redis_client: Optional[aioredis.Redis] = None,
    ) -> None:
        self._redis = redis_client
        self._db    = db_client

        # Shared incident tracker (used by both quick path and background path)
        self._incident_tracker = IncidentTracker(
            db_client=db_client,
            redis_client=redis_client,
        )

        # Path B
        self._quick = QuickCorrelationEngine(redis_client=redis_client)

        # Path C
        self._background = BackgroundCorrelationEngine(
            incident_tracker=self._incident_tracker,
            db_client=db_client,
            redis_client=redis_client,
        )

    def start(self) -> None:
        """Launch background correlation workers. Call once at application startup."""
        self._background.start()
        logger.info("HybridCorrelationSystem: started (quick + background workers)")

    # ------------------------------------------------------------------
    # Main entry point (called per alert from AlertProcessor)
    # ------------------------------------------------------------------

    async def handle_alert(self, alert: Dict[str, Any]) -> CorrelationHandleResult:
        """
        Orchestrate all correlation paths for a newly processed alert.

        Returns immediately (does not block on deep correlation).
        """
        alert_id = str(alert.get("alert_id", ""))

        # ─── Path B: Quick Correlation (awaited, <5 s) ────────────────────
        quick_results: List[CorrelationResult] = await self._quick.quick_correlate(alert)

        incident_id: Optional[str] = None

        # If quick correlation found high-confidence hits → create/update incident now
        high_conf = [r for r in quick_results if r.confidence >= QUICK_CONFIDENCE_THRESHOLD]
        if high_conf and self._incident_tracker:
            from .models import AlertRef
            ref      = AlertRef.from_alert(alert)
            related  = list({aid for r in high_conf for aid in r.related_alert_ids})
            existing = await self._incident_tracker.find_incident_by_alerts(related + [alert_id])

            if existing:
                updated = await self._incident_tracker.add_alert_to_incident(
                    existing["incident_id"], ref, high_conf
                )
                incident_id = existing["incident_id"]
                logger.info(
                    f"Quick corr: alert {alert_id} added to incident {incident_id}"
                )
            else:
                # Build refs for related alerts
                from .models import AlertRef as AR
                alert_refs = [ref]
                if self._db and related:
                    docs = list(self._db.alerts.find(
                        {"alert_id": {"$in": related}},
                        {"alert_id": 1, "user": 1, "source_ip": 1, "severity": 1,
                         "enrichments": 1, "mitre_technique": 1, "actor": 1, "src_endpoint": 1},
                    ))
                    alert_refs += [AR.from_alert(d) for d in docs]

                created = await self._incident_tracker.create_incident(
                    alert_refs, high_conf
                )
                if created:
                    incident_id = created["incident_id"]
                    logger.info(
                        f"Quick corr: new incident {incident_id} created for alert {alert_id}"
                    )

        # ─── Path C: Deep Correlation (enqueue, non-blocking) ─────────────
        deep_queued = await self._background.enqueue(alert)

        return CorrelationHandleResult(
            alert_id=alert_id,
            quick_correlations=quick_results,
            incident_id=incident_id,
            deep_queued=deep_queued,
        )

    # ------------------------------------------------------------------
    # Observability helpers (called by /metrics endpoint)
    # ------------------------------------------------------------------

    @property
    def queue_depth(self) -> int:
        return self._background.queue_depth

    @property
    def overflow_count(self) -> int:
        return self._background.overflow_count
