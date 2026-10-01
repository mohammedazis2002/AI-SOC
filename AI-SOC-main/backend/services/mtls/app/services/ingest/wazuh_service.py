import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ASCENDING

logger = logging.getLogger(__name__)

# ── Collections
RAW_ALERTS_COLLECTION = "alerts_raw"
NORMALISED_ALERTS_COLLECTION = "alerts_processed"
DLQ_ALERTS_COLLECTION = "unmapped_alerts"


# ── Result dataclass ──────────────────────────────────────────────────────────


class ProcessingResult:
    def __init__(
        self,
        success: bool,
        alert_id: Optional[str],
        normalised: bool,
        dlq: bool,
        message: str,
    ):
        self.success = success
        self.alert_id = alert_id
        self.normalised = normalised
        self.dlq = dlq
        self.message = message


# ── Public entry point ────────────────────────────────────────────────────────


async def process_wazuh_alert(
    alert,  # WazuhAlert Pydantic model
    cert_info: Dict[str, Any],
    db: AsyncIOMotorDatabase,
) -> ProcessingResult:
    """
    Full pipeline:
      raw alert → NormalisationAgent → AlertProcessor → MongoDB

    Args:
        alert:     Validated WazuhAlert from the router.
        cert_info: mTLS cert metadata (common_name, etc.).
        db:        Motor async database handle from app.database.

    Returns:
        ProcessingResult with status fields for the router to use.
    """
    # FIX: _ensure_indexes removed here — now handled once inside
    # AlertProcessor.start() → HybridCorrelationSystem.start() → ensure_indexes()
    await _ensure_indexes(db)

    # Step 1: Convert Pydantic → raw dict
    raw_dict = _to_raw_dict(alert, cert_info)

    # Step 2: Persist raw alert (upsert on Wazuh's own id)
    await _store_raw(db, raw_dict, alert.id)

    # ── Step 3: Queue for Async Processing ────────────────────────────────────
    try:
        from backend.services.ingestion.queue_manager import get_queue_manager

        queue_manager = await get_queue_manager()
        push_result = await queue_manager.push_alert(raw_dict, priority=False)

        # Dedupe: same id/source_alert_id within TTL does not enqueue again (no new Redis message).
        if push_result == "deduped":
            logger.warning(
                "Alert %s not enqueued: duplicate within REDIS_INGEST_DEDUPE_TTL_SECONDS "
                "(same id/source_alert_id/alert_id). Worker will not see a new stream entry.",
                alert.id,
            )
            return ProcessingResult(
                success=True,
                alert_id=alert.id,
                normalised=False,
                dlq=False,
                message=(
                    "Alert accepted but not re-queued: duplicate within dedupe window "
                    "(change alert id or wait for TTL / clear Redis dedupe key)."
                ),
            )

        logger.info(
            "Alert %s queued for background processing (redis_msg=%s)",
            alert.id,
            push_result,
        )
        return ProcessingResult(
            success=True,
            alert_id=alert.id,
            normalised=False,  # Not normalised yet
            dlq=False,
            message="Alert queued for background processing",
        )
    except Exception as e:
        logger.error(f"Failed to queue alert {alert.id}: {e}", exc_info=True)
        # Fallback: store in DLQ if queue fails
        await _store_dlq(
            db, raw_dict, alert.id, ulf=None, errors=[str(e)], reason="queue_failure"
        )
        return ProcessingResult(
            success=False,
            alert_id=alert.id,
            normalised=False,
            dlq=True,
            message=f"Failed to queue alert: {e}",
        )


# ── DB Helpers ────────────────────────────────────────────────────────────────


async def _store_raw(
    db: AsyncIOMotorDatabase,
    raw_dict: Dict,
    wazuh_id: str,
) -> None:
    """Upsert raw alert. Uses Wazuh's own id as _id for deduplication."""
    try:
        await db[RAW_ALERTS_COLLECTION].update_one(
            {"_id": wazuh_id},
            {
                "$setOnInsert": {
                    "_id": wazuh_id,
                    "raw": raw_dict,
                    "received_at": datetime.now(timezone.utc),
                }
            },
            upsert=True,
        )
    except Exception as e:
        logger.error(f"Failed to store raw alert {wazuh_id}: {e}")


async def _store_normalised(
    db: AsyncIOMotorDatabase,
    ulf: Dict,
    wazuh_id: str,
) -> None:
    """Upsert normalised ULF. Uses agent-generated alert_id as _id."""
    try:
        doc = _serialise_ulf(ulf)
        doc["_id"] = ulf.get("alert_id", wazuh_id)
        doc["source_raw_id"] = wazuh_id
        doc["stored_at"] = datetime.now(timezone.utc)

        await db[NORMALISED_ALERTS_COLLECTION].update_one(
            {"_id": doc["_id"]},
            {"$set": doc},
            upsert=True,
        )
    except Exception as e:
        logger.error(f"Failed to store normalised alert for {wazuh_id}: {e}")


async def _store_dlq(
    db: AsyncIOMotorDatabase,
    raw_dict: Dict,
    wazuh_id: str,
    ulf: Optional[Dict],
    errors: list,
    reason: str,
) -> None:
    """Insert a DLQ entry. Always inserts (no dedup — analysts need full history)."""
    try:
        await db[DLQ_ALERTS_COLLECTION].insert_one(
            {
                "source_raw_id": wazuh_id,
                "raw": raw_dict,
                "partial_ulf": _serialise_ulf(ulf) if ulf else None,
                "errors": errors,
                "reason": reason,
                "queued_at": datetime.now(timezone.utc),
                "reviewed": False,
            }
        )
    except Exception as e:
        logger.error(f"Failed to store DLQ entry for {wazuh_id}: {e}")


async def _ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    """
    Create indexes for raw/normalised/dlq collections.
    Safe to call on every request — Motor is idempotent on existing indexes.
    Note: incident_tracker indexes are handled separately via AlertProcessor.start().
    """
    try:
        await db[RAW_ALERTS_COLLECTION].create_index([("received_at", ASCENDING)])
        await db[NORMALISED_ALERTS_COLLECTION].create_index(
            [("severity_id", ASCENDING), ("stored_at", ASCENDING)]
        )
        await db[NORMALISED_ALERTS_COLLECTION].create_index([("class_uid", ASCENDING)])
        await db[NORMALISED_ALERTS_COLLECTION].create_index(
            [("siem_source", ASCENDING)]
        )
        await db[DLQ_ALERTS_COLLECTION].create_index(
            [("reviewed", ASCENDING), ("queued_at", ASCENDING)]
        )
    except Exception as e:
        logger.warning(f"Index creation skipped (non-fatal): {e}")


# ── Conversion Helpers ────────────────────────────────────────────────────────


def _to_raw_dict(alert, cert_info: Dict) -> Dict:
    """
    Convert WazuhAlert Pydantic model to the raw dict format
    NormalisationAgent expects (mirrors Wazuh's native JSON structure).
    """
    raw = alert.model_dump(mode="python")
    if not raw.get("full_log"):
        # Some forwarders emit structured JSON without a raw `full_log` string.
        # Preserve a readable message for downstream tooling/analysts.
        rule = raw.get("rule") or {}
        raw["full_log"] = rule.get("description") or ""
    raw["_ingestion_meta"] = {
        "received_from": cert_info.get("common_name", "unknown"),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    return raw


def _serialise_ulf(ulf: Dict) -> Dict:
    """
    Convert datetime objects in the ULF to ISO strings for MongoDB storage.
    Motor handles datetimes natively but nested dicts with datetime need help.
    """
    import json

    return json.loads(json.dumps(ulf, default=str))
