"""
Dead Letter Queue Handler
=========================
Sends unrecoverable or hard-failed alerts to a persistent DLQ so they are
never silently dropped.

DLQ destinations:
  1. MongoDB collection: `normalisation_dlq` (full context, queryable)
  2. Redis list: `norm:dlq:pending` (for monitoring dashboard)

DLQ reasons:
  - "missing_desc_high_severity"  → HIGH/CRITICAL alert with no description (hard fail)
  - "max_retries_minimal_ulf"     → Alert normalised to bare minimum after 3 retries
  - "unrecoverable"               → All retries exhausted, no valid ULF produced

On DLQ entry, analyst can:
  - Add missing fields and resubmit via POST /normalization/resubmit/{dlq_id}
  - Reject (mark as noise)
  - In dashboard: visible under "Normalization Review" queue
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DLQ_REDIS_KEY = "norm:dlq:pending"


class DLQHandler:
    """Manages the normalization Dead Letter Queue."""

    def __init__(self, mongo_db=None, redis_client=None):
        self._db = mongo_db
        self._redis = redis_client

    async def send(
        self,
        raw_alert: Dict[str, Any],
        partial_ulf: Optional[Dict[str, Any]],
        validation_errors: List[str],
        reason: str,
    ) -> str:
        """
        Persist a failed alert to the DLQ.

        Args:
            raw_alert:         Original raw alert (always preserved)
            partial_ulf:       Best ULF attempt (may be None or incomplete)
            validation_errors: Pydantic validation errors from last attempt
            reason:            Why it failed — one of the reason codes above

        Returns:
            dlq_id: Unique DLQ record ID for resubmission
        """
        dlq_id = str(uuid.uuid4())
        source_id = raw_alert.get("_id", "")
        index = raw_alert.get("_index", "")

        entry = {
            "dlq_id": dlq_id,
            "reason": reason,
            "source_id": source_id,
            "source_index": index,
            "raw_alert": raw_alert,
            "partial_ulf": partial_ulf,
            "validation_errors": validation_errors,
            "status": "pending_review",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "retry_count": 0,
        }

        # Store in MongoDB
        try:
            if self._db is not None:
                self._db.normalisation_dlq.insert_one(entry)
                logger.info(
                    f"DLQ: stored {dlq_id} (reason={reason}, source={source_id!r})"
                )
        except Exception as e:
            logger.error(f"DLQ MongoDB write failed: {e}")

        # Push to Redis list for dashboard counter
        try:
            if self._redis:
                await self._redis.lpush(
                    DLQ_REDIS_KEY,
                    json.dumps({"dlq_id": dlq_id, "reason": reason, "source_id": source_id}),
                )
                await self._redis.ltrim(DLQ_REDIS_KEY, 0, 9999)  # cap at 10k entries
        except Exception as e:
            logger.warning(f"DLQ Redis push failed: {e}")

        logger.warning(
            f"Alert DLQ'd [{dlq_id[:8]}] reason={reason!r} "
            f"errors={validation_errors[:2]}"
        )
        return dlq_id
