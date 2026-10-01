from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models import COLLECTION_AUDIT_LOGS


async def write_audit(
    db: AsyncIOMotorDatabase,
    *,
    action: str,
    actor_id: str,
    target_user_id: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    doc: dict[str, Any] = {
        "action": action,
        "actor_id": actor_id,
        "target_user_id": target_user_id,
        "details": details or {},
        "created_at": datetime.now(timezone.utc),
    }
    await db[COLLECTION_AUDIT_LOGS].insert_one(doc)
