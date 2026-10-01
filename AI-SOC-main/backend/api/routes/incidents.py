"""
Incidents API Routes
=====================
REST endpoints for the correlation-engine-managed Incidents collection.

Auth: Uses the same API key validation as ingestion routes.
PATCH requires analyst privileges (for now, any valid key suffices — extend with role claims).

All queries go through IncidentTracker; no direct MongoDB access from routes.
"""

from fastapi import APIRouter, HTTPException, Header, Query, status
from fastapi.responses import JSONResponse
from typing import Optional, List
from datetime import datetime
from pymongo import MongoClient, DESCENDING
import logging
import os
import json

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

# Simple API-key auth (mirrors ingestion.py)
# API keys are loaded from environment to avoid hard-coding secrets.
def _load_valid_api_keys() -> dict:
    """
    Load API keys from the INCIDENTS_VALID_API_KEYS environment variable.

    Expected format (JSON object):
        {"wazuh-api-key-12345": "wazuh", "sentinelone-api-key-67890": "sentinelone"}
    """
    raw = os.getenv("INCIDENTS_VALID_API_KEYS")
    if not raw:
        logger.warning(
            "INCIDENTS_VALID_API_KEYS is not set; incidents routes will reject all API-key auth"
        )
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("INCIDENTS_VALID_API_KEYS must be a JSON object mapping keys to sources")
        # Normalize keys/values to strings
        return {str(k): str(v) for k, v in data.items()}
    except Exception as exc:
        logger.error(
            "Failed to parse INCIDENTS_VALID_API_KEYS; incidents routes will reject all API-key auth",
            exc_info=exc,
        )
        return {}

VALID_API_KEYS = _load_valid_api_keys()

# Module-level MongoClient cache to avoid creating a new client per request.
_mongo_client: Optional[MongoClient] = None

def _get_db():
    """Lazy MongoDB connection (reuses MongoClient per-process)."""
    global _mongo_client
    host = os.getenv("MONGODB_HOST", "localhost")
    port = int(os.getenv("MONGODB_PORT", "27017"))
    user = os.getenv("MONGODB_USERNAME", "")
    pwd  = os.getenv("MONGODB_PASSWORD", "")
    db_name = os.getenv("MONGODB_DATABASE", "soar_db")
    if _mongo_client is None:
        if user and pwd:
            uri = f"mongodb://{user}:{pwd}@{host}:{port}/"
        else:
            uri = f"mongodb://{host}:{port}/"
        _mongo_client = MongoClient(uri)
    return _mongo_client[db_name]

def _validate_api_key(key: Optional[str]) -> str:
    if not key or key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
    return VALID_API_KEYS[key]


# ---------------------------------------------------------------------------
# GET /api/incidents  — list incidents
# ---------------------------------------------------------------------------

@router.get("", status_code=status.HTTP_200_OK)
async def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity: critical|high|medium|low"),
    incident_status: Optional[str] = Query(None, alias="status", description="Filter by status: open|in_progress|resolved|false_positive"),
    limit: int = Query(50, ge=1, le=200),
    skip: int = Query(0, ge=0),
    x_api_key: Optional[str] = Header(None),
):
    """
    List incidents, newest first. Supports severity/status filters and pagination.
    """
    _validate_api_key(x_api_key)
    db = _get_db()

    query = {}
    if severity:
        query["severity"] = severity.lower()
    if incident_status:
        query["status"] = incident_status.lower()

    cursor = (
        db.incidents
        .find(query, {"_id": 0})
        .sort("created_at", DESCENDING)
        .skip(skip)
        .limit(limit)
    )
    incidents = list(cursor)
    total = db.incidents.count_documents(query)

    # Serialise datetime objects
    for inc in incidents:
        for k, v in inc.items():
            if isinstance(v, datetime):
                inc[k] = v.isoformat()

    return JSONResponse(content={
        "incidents": _serialise_list(incidents),
        "total": total,
        "limit": limit,
        "skip": skip,
    })


# ---------------------------------------------------------------------------
# GET /api/incidents/{incident_id}  — get single incident
# ---------------------------------------------------------------------------

@router.get("/{incident_id}", status_code=status.HTTP_200_OK)
async def get_incident(
    incident_id: str,
    x_api_key: Optional[str] = Header(None),
):
    """Get a single incident with full detail."""
    _validate_api_key(x_api_key)
    db = _get_db()

    doc = db.incidents.find_one({"incident_id": incident_id}, {"_id": 0})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    return JSONResponse(content=_serialise(doc))


# ---------------------------------------------------------------------------
# PATCH /api/incidents/{incident_id}  — analyst update
# ---------------------------------------------------------------------------

@router.patch("/{incident_id}", status_code=status.HTTP_200_OK)
async def update_incident(
    incident_id: str,
    update: dict,
    x_api_key: Optional[str] = Header(None),
):
    """
    Update an incident's status or analyst notes.
    Allowed fields: status, analyst_notes, severity.
    """
    _validate_api_key(x_api_key)
    db = _get_db()

    allowed = {"status", "analyst_notes", "severity"}
    changes = {k: v for k, v in update.items() if k in allowed}
    if not changes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No updatable fields provided. Allowed: {sorted(allowed)}",
        )

    changes["updated_at"] = datetime.utcnow()

    # If resolved, set resolved_at for TTL index
    if changes.get("status") == "resolved":
        changes["resolved_at"] = datetime.utcnow()

    result = db.incidents.update_one(
        {"incident_id": incident_id},
        {"$set": changes},
    )
    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    # Audit log
    try:
        db.audit_log.insert_one({
            "event": "incident_updated",
            "incident_id": incident_id,
            "changes": {k: str(v) for k, v in changes.items()},
            "ts": datetime.utcnow(),
        })
    except Exception as exc:
        logger.warning(f"Audit log write failed: {exc}")

    updated = db.incidents.find_one({"incident_id": incident_id}, {"_id": 0})
    return JSONResponse(content=_serialise(updated))


# ---------------------------------------------------------------------------
# GET /api/incidents/{incident_id}/timeline  — alert timeline
# ---------------------------------------------------------------------------

@router.get("/{incident_id}/timeline", status_code=status.HTTP_200_OK)
async def get_incident_timeline(
    incident_id: str,
    x_api_key: Optional[str] = Header(None),
):
    """
    Return the ordered alert timeline for an incident.
    Pulls alerts from the alerts collection by their alert_id.
    """
    _validate_api_key(x_api_key)
    db = _get_db()

    doc = db.incidents.find_one({"incident_id": incident_id}, {"alert_refs": 1})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    alert_ids = [r["alert_id"] for r in doc.get("alert_refs", []) if r.get("alert_id")]

    alerts = list(
        db.alerts
        .find({"alert_id": {"$in": alert_ids}}, {"_id": 0})
        .sort("time", 1)
    )

    return JSONResponse(content={
        "incident_id": incident_id,
        "alerts": _serialise_list(alerts),
        "count": len(alerts),
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialise(doc: dict) -> dict:
    """Convert non-JSON-serialisable values (e.g. datetime) to strings."""
    if doc is None:
        return {}
    out = {}
    for k, v in doc.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        elif isinstance(v, list):
            out[k] = [_serialise(i) if isinstance(i, dict) else (i.isoformat() if isinstance(i, datetime) else i) for i in v]
        elif isinstance(v, dict):
            out[k] = _serialise(v)
        else:
            out[k] = v
    return out


def _serialise_list(docs: list) -> list:
    return [_serialise(d) if isinstance(d, dict) else d for d in docs]
