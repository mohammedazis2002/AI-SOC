"""
Correlation Engine – Incident Tracker
======================================
MongoDB-backed incident lifecycle management.

Responsibilities:
  - Create new incidents from correlated alert clusters
  - Add new alerts to existing incidents (retroactive linking)
  - Upgrade severity when new evidence warrants it
  - Maintain an append-only audit log for every mutation
  - Ensure idempotency via SHA-256-derived incident IDs

Security / Robustness:
  - All queries use Pydantic-validated dicts; no raw string interpolation
  - Distributed Redis lock acquired before create to prevent duplicate incidents
  - MongoDB TTL index on resolved_at purges old incidents after INCIDENT_RETENTION_DAYS
  - MongoDB indexes pre-created at startup for fast analyst queries
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from pymongo import ASCENDING, IndexModel, MongoClient
from pymongo.collection import Collection

from .models import (
    AlertRef,
    CorrelationResult,
    Incident,
    IncidentSeverity,
    IncidentStatus,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants (overridable via env)
# ---------------------------------------------------------------------------
REDIS_LOCK_TTL_MS       = int(os.getenv("CORR_LOCK_TTL_MS", "10000"))   # 10 s
INCIDENT_RETENTION_DAYS = int(os.getenv("INCIDENT_RETENTION_DAYS", "365"))
LOCK_RETRY_ATTEMPTS     = 3
LOCK_RETRY_DELAY_S      = 0.3

_SEVERITY_RANK: Dict[str, int] = {
    IncidentSeverity.CRITICAL: 4,
    IncidentSeverity.HIGH: 3,
    IncidentSeverity.MEDIUM: 2,
    IncidentSeverity.LOW: 1,
}


# ---------------------------------------------------------------------------
# Helper: deterministic incident ID from a set of alert IDs
# ---------------------------------------------------------------------------

def _make_incident_id(alert_ids: List[str]) -> str:
    """
    SHA-256 of sorted alert IDs → first 16 hex chars.
    Guarantees the same set of alerts always maps to the same incident_id,
    preventing duplicate incidents even if the Redis lock fails.
    """
    payload = json.dumps(sorted(alert_ids), separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# IncidentTracker
# ---------------------------------------------------------------------------

class IncidentTracker:
    """
    Manages the incident lifecycle backed by MongoDB.

    Instantiate once and share across the process:
        tracker = IncidentTracker(db_client, redis_client)
    """

    def __init__(
        self,
        db_client: Optional[MongoClient] = None,
        redis_client: Optional[aioredis.Redis] = None,
    ) -> None:
        # Accept either a MongoClient or a database object; never rely on truthiness.
        if db_client is None:
            _db = MongoClient()["soar_db"]
        elif isinstance(db_client, MongoClient):
            _db = db_client["soar_db"]
        else:
            # assume it's already a DB-like object (Motor or PyMongo database)
            _db = db_client

        self._incidents = _db.incidents
        self._alerts = _db.alerts
        self._audit_log = _db.audit_log

        self._redis = redis_client
        self._ensure_indexes()

    # ------------------------------------------------------------------
    # Index creation
    # ------------------------------------------------------------------

    def _ensure_indexes(self) -> None:
        """Create all necessary MongoDB indexes (idempotent)."""
        try:
            self._incidents.create_indexes([
                IndexModel([("incident_id", ASCENDING)],    unique=True),
                IndexModel([("status", ASCENDING)]),
                IndexModel([("severity", ASCENDING), ("status", ASCENDING)]),
                IndexModel([("created_at", ASCENDING)]),
                IndexModel([("alert_refs.alert_id", ASCENDING)]),
                # TTL: auto-purge resolved incidents after retention period
                IndexModel(
                    [("resolved_at", ASCENDING)],
                    expireAfterSeconds=INCIDENT_RETENTION_DAYS * 86400,
                    sparse=True,
                ),
            ])
            # Audit log – never delete, but index by incident_id + ts
            self._audit_log.create_indexes([
                IndexModel([("incident_id", ASCENDING), ("ts", ASCENDING)]),
            ])
            logger.info("IncidentTracker: MongoDB indexes created/verified")
        except Exception as exc:
            logger.warning(f"IncidentTracker: index creation warning: {exc}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def find_incident_by_alerts(
        self,
        alert_ids: List[str],
    ) -> Optional[Dict[str, Any]]:
        """Return an existing incident doc containing ANY of the given alert_ids."""
        try:
            doc = self._incidents.find_one(
                {"alert_refs.alert_id": {"$in": alert_ids}, "status": {"$ne": IncidentStatus.FALSE_POS}},
                sort=[("created_at", -1)],
            )
            return doc
        except Exception as exc:
            logger.error(f"IncidentTracker.find_incident_by_alerts error: {exc}")
            return None

    async def create_incident(
        self,
        alerts: List[AlertRef],
        correlation_results: List[CorrelationResult],
        narrative: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Create a new incident, idempotently.

        Uses a Redis distributed lock + deterministic incident_id to prevent
        duplicate incidents from concurrent background workers.
        """
        alert_ids   = [a.alert_id for a in alerts]
        incident_id = _make_incident_id(alert_ids)

        # Acquire Redis lock (best-effort; fall back to idempotent upsert if unavailable)
        lock_acquired = await self._acquire_lock(f"corr:lock:incident:{incident_id}")

        try:
            # Idempotent upsert — even without the lock, SHA-256 ID prevents duplicates
            now      = datetime.utcnow()
            severity = self._derive_severity(alerts, correlation_results)
            confidence = max((r.confidence for r in correlation_results), default=0.0)
            attack_pattern = next(
                (r.attack_pattern for r in correlation_results if r.attack_pattern),
                None,
            )

            incident_doc = {
                "incident_id":         incident_id,
                "severity":            severity,
                "status":              IncidentStatus.OPEN,
                "alert_refs":          [a.to_cache_dict() for a in alerts],
                "correlation_results": [r.model_dump() for r in correlation_results],
                "narrative":           narrative,
                "attack_pattern":      attack_pattern,
                "confidence":          confidence,
                "created_at":          now,
                "updated_at":          now,
                "resolved_at":         None,
            }

            result = self._incidents.update_one(
                {"incident_id": incident_id},
                {"$setOnInsert": incident_doc},
                upsert=True,
            )

            if result.upserted_id:
                logger.info(f"Incident {incident_id} CREATED (severity={severity}, alerts={len(alerts)})")
                await self._audit("incident_created", incident_id, {
                    "alert_ids": alert_ids, "confidence": confidence, "severity": severity,
                })
                # Retroactively link all old alert docs
                for alert_id in alert_ids:
                    await self.update_alert_status_in_mongo(alert_id, incident_id)
            else:
                logger.debug(f"Incident {incident_id} already exists (idempotent upsert)")

            return self._incidents.find_one({"incident_id": incident_id})

        except Exception as exc:
            logger.error(f"IncidentTracker.create_incident error: {exc}", exc_info=True)
            return None
        finally:
            if lock_acquired:
                await self._release_lock(f"corr:lock:incident:{incident_id}")

    async def add_alert_to_incident(
        self,
        incident_id: str,
        alert: AlertRef,
        correlation_results: List[CorrelationResult],
    ) -> Optional[Dict[str, Any]]:
        """Add a new alert to an existing incident; upgrade severity if needed."""
        try:
            existing = self._incidents.find_one({"incident_id": incident_id})
            if not existing:
                logger.warning(f"add_alert_to_incident: incident {incident_id} not found")
                return None

            now = datetime.utcnow()
            new_confidence = max(
                (r.confidence for r in correlation_results), default=0.0
            )

            # Upgrade severity if new evidence warrants it
            new_severity = self._derive_severity([alert], correlation_results)
            current_severity = existing.get("severity", IncidentSeverity.LOW)
            if _SEVERITY_RANK.get(new_severity, 0) > _SEVERITY_RANK.get(current_severity, 0):
                severity_to_set = new_severity
                logger.info(f"Incident {incident_id}: severity upgraded {current_severity} → {new_severity}")
                await self._audit("severity_upgraded", incident_id, {
                    "from": current_severity, "to": new_severity, "triggered_by": alert.alert_id,
                })
            else:
                severity_to_set = current_severity

            self._incidents.update_one(
                {"incident_id": incident_id},
                {
                    "$addToSet": {"alert_refs": alert.to_cache_dict()},
                    "$push":    {"correlation_results": {"$each": [r.model_dump() for r in correlation_results]}},
                    "$set": {
                        "severity":   severity_to_set,
                        "confidence": max(existing.get("confidence", 0.0), new_confidence),
                        "updated_at": now,
                        "status":     IncidentStatus.OPEN,  # re-open if resolved
                    },
                },
            )

            await self._audit("alert_added", incident_id, {"alert_id": alert.alert_id})
            await self.update_alert_status_in_mongo(alert.alert_id, incident_id)

            return self._incidents.find_one({"incident_id": incident_id})

        except Exception as exc:
            logger.error(f"IncidentTracker.add_alert_to_incident error: {exc}", exc_info=True)
            return None

    async def update_alert_status_in_mongo(
        self,
        alert_id: str,
        incident_id: str,
    ) -> None:
        """Retroactively link an existing alert document to this incident."""
        try:
            self._alerts.update_one(
                {"alert_id": alert_id},
                {"$set": {"incident_id": incident_id, "status": "part_of_incident"}},
            )
        except Exception as exc:
            logger.warning(f"Could not retroactively link alert {alert_id}: {exc}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_severity(
        alerts: List[AlertRef],
        correlation_results: List[CorrelationResult],
    ) -> str:
        """Derive incident severity from alert severities and confidence."""
        sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_sev = max(
            (sev_map.get(str(a.severity).lower(), 2) for a in alerts),
            default=2,
        )
        max_confidence = max((r.confidence for r in correlation_results), default=0.0)

        # Escalate one level if confidence is very high
        if max_confidence >= 0.9 and max_sev < 4:
            max_sev += 1

        inv_map = {4: "critical", 3: "high", 2: "medium", 1: "low"}
        return inv_map.get(min(max_sev, 4), "medium")

    async def _acquire_lock(self, key: str) -> bool:
        """Try to acquire a Redis distributed lock (NX + PX). Returns True if acquired."""
        if not self._redis:
            return False
        for attempt in range(LOCK_RETRY_ATTEMPTS):
            try:
                acquired = await self._redis.set(
                    key, "1", nx=True, px=REDIS_LOCK_TTL_MS
                )
                if acquired:
                    return True
                if attempt < LOCK_RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(LOCK_RETRY_DELAY_S)
            except Exception as exc:
                logger.warning(f"Redis lock acquire failed ({key}): {exc}")
                return False
        return False

    async def _release_lock(self, key: str) -> None:
        if not self._redis:
            return
        try:
            await self._redis.delete(key)
        except Exception as exc:
            logger.warning(f"Redis lock release failed ({key}): {exc}")

    async def _audit(
        self,
        event: str,
        incident_id: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append an audit event. Never raises — audit failures are logged, not fatal."""
        try:
            entry = {
                "event":       event,
                "incident_id": incident_id,
                "ts":          datetime.utcnow(),
                **(extra or {}),
            }
            self._audit_log.insert_one(entry)
        except Exception as exc:
            logger.warning(f"Audit log write failed ({event}, {incident_id}): {exc}")
