"""
JumpCloud Webhook Receiver
===========================
FastAPI router that receives real-time events from JumpCloud webhooks and
keeps `asset_inventory` + `user_inventory` MongoDB collections up to date.

Registration:
    JumpCloud Console → Integrations → Webhooks → Add Webhook
    URL: https://your-soar-backend.example.com/integrations/jumpcloud/events
    Secret: set JUMPCLOUD_WEBHOOK_SECRET env var (HMAC-SHA256 verification)

Supported events:
    system.created          → upsert new asset record
    system.delete           → mark asset inactive (not hard delete)
    user.created            → upsert user record
    user.delete             → mark user suspended
    user.lock               → mark user locked
    user.activate           → mark user active
    user.add_to_group       → no asset_inventory change (group mgmt)
    system.user.bind        → add user to asset's accessed_by_users[]
    system.user.unbind      → remove user from asset's accessed_by_users[]

Mount in your FastAPI app:
    from services.integrations.jumpcloud_webhook import router as jc_router
    app.include_router(jc_router)
"""

import hashlib
import hmac
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pymongo import MongoClient

logger = logging.getLogger("jumpcloud_webhook")

router = APIRouter(prefix="/integrations/jumpcloud", tags=["jumpcloud"])

# ── Dependency: MongoDB ───────────────────────────────────────────────────────

def get_db():
    client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"))
    try:
        yield client[os.getenv("MONGO_DB", "soar_db")]
    finally:
        client.close()


# ── HMAC Signature Verification ───────────────────────────────────────────────

WEBHOOK_SECRET = os.getenv("JUMPCLOUD_WEBHOOK_SECRET", "")


async def verify_signature(
    request: Request,
    x_jumpcloud_signature: str = Header(None),
):
    """Verify JumpCloud HMAC-SHA256 webhook signature."""
    if not WEBHOOK_SECRET:
        logger.warning("JUMPCLOUD_WEBHOOK_SECRET not set — skipping signature verification")
        return

    body = await request.body()
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256
    ).hexdigest()

    if not x_jumpcloud_signature:
        raise HTTPException(status_code=401, detail="Missing X-JumpCloud-Signature header")

    if not hmac.compare_digest(expected, x_jumpcloud_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


# ── Event Router ─────────────────────────────────────────────────────────────

@router.post("/events", dependencies=[Depends(verify_signature)])
async def handle_event(request: Request, db=Depends(get_db)):
    """Receive and process a JumpCloud webhook event."""
    payload: Dict[str, Any] = await request.json()

    event_type = payload.get("event_type", "")
    data       = payload.get("data", {})

    logger.info(f"JumpCloud webhook received: event_type={event_type}")

    handlers = {
        "system.created":        _on_system_created,
        "system.delete":         _on_system_deleted,
        "user.created":          _on_user_created,
        "user.delete":           _on_user_deleted,
        "user.lock":             _on_user_locked,
        "user.activate":         _on_user_activated,
        "system.user.bind":      _on_user_bound_to_system,
        "system.user.unbind":    _on_user_unbound_from_system,
    }

    handler = handlers.get(event_type)
    if handler:
        await handler(data, db)
    else:
        logger.debug(f"No handler for event_type: {event_type} — ignoring")

    return {"status": "ok", "event_type": event_type}


# ── Event Handlers ────────────────────────────────────────────────────────────

async def _on_system_created(data: Dict, db):
    """A new device was enrolled in JumpCloud."""
    from scripts.setup.bootstrap_jumpcloud_api import build_asset_from_api
    asset = build_asset_from_api(data, user_id_to_doc={})
    asset["last_seen"] = _now()
    db.asset_inventory.update_one(
        {"asset_id": asset["asset_id"]},
        {"$set": asset},
        upsert=True,
    )
    logger.info(f"system.created → upserted asset {asset['hostname']}")


async def _on_system_deleted(data: Dict, db):
    """A device was removed/decommissioned from JumpCloud."""
    system_id = data.get("id") or data.get("system_id") or data.get("_id")
    if not system_id:
        return

    db.asset_inventory.update_one(
        {"asset_id": system_id},
        {"$set": {
            "active":       False,
            "decommissioned_at": _now(),
            "last_seen":    _now(),
        }},
    )
    logger.info(f"system.delete → marked asset {system_id} inactive")


async def _on_user_created(data: Dict, db):
    """A new user account was created in JumpCloud."""
    user_doc = {
        "user_id":      data.get("id", ""),
        "username":     data.get("username", ""),
        "email":        data.get("email", ""),
        "first_name":   data.get("firstname", ""),
        "last_name":    data.get("lastname", ""),
        "is_admin":     data.get("admin", False),
        "is_suspended": data.get("suspended", False),
        "is_activated": data.get("activated", True),
        "device_ids":   [],
        "source":       "jumpcloud_webhook",
        "last_updated": _now(),
    }
    db.user_inventory.update_one(
        {"username": user_doc["username"]},
        {"$set": user_doc},
        upsert=True,
    )
    logger.info(f"user.created → upserted user {user_doc['username']}")


async def _on_user_deleted(data: Dict, db):
    """A user account was deleted/deactivated."""
    username = data.get("username") or data.get("id")
    if not username:
        return
    db.user_inventory.update_one(
        {"$or": [{"username": username}, {"user_id": username}]},
        {"$set": {
            "is_suspended": True,
            "is_activated": False,
            "deleted_at":   _now(),
            "last_updated": _now(),
        }},
    )
    logger.info(f"user.delete → suspended user {username}")


async def _on_user_locked(data: Dict, db):
    """A user account was locked."""
    username = data.get("username") or data.get("id")
    if not username:
        return
    db.user_inventory.update_one(
        {"$or": [{"username": username}, {"user_id": username}]},
        {"$set": {"is_suspended": True, "lock_reason": "jumpcloud_lock", "last_updated": _now()}},
    )
    logger.info(f"user.lock → locked user {username}")


async def _on_user_activated(data: Dict, db):
    """A previously locked/suspended user was reactivated."""
    username = data.get("username") or data.get("id")
    if not username:
        return
    db.user_inventory.update_one(
        {"$or": [{"username": username}, {"user_id": username}]},
        {"$set": {"is_suspended": False, "is_activated": True, "last_updated": _now()}},
    )
    logger.info(f"user.activate → reactivated user {username}")


async def _on_user_bound_to_system(data: Dict, db):
    """
    A user was associated with a system (device).
    Update BOTH asset_inventory.accessed_by_users[] AND user_inventory.device_ids[].
    """
    system_id = data.get("system_id") or data.get("_id")
    username  = data.get("username")
    user_id   = data.get("user_id")

    if system_id and username:
        db.asset_inventory.update_one(
            {"asset_id": system_id},
            {"$addToSet": {"accessed_by_users": username}, "$set": {"last_seen": _now()}},
        )

    if user_id and system_id:
        db.user_inventory.update_one(
            {"user_id": user_id},
            {"$addToSet": {"device_ids": system_id}, "$set": {"last_updated": _now()}},
        )
    logger.info(f"system.user.bind → user {username} bound to system {system_id}")


async def _on_user_unbound_from_system(data: Dict, db):
    """A user was disassociated from a system."""
    system_id = data.get("system_id") or data.get("_id")
    username  = data.get("username")
    user_id   = data.get("user_id")

    if system_id and username:
        db.asset_inventory.update_one(
            {"asset_id": system_id},
            {"$pull": {"accessed_by_users": username}, "$set": {"last_seen": _now()}},
        )

    if user_id and system_id:
        db.user_inventory.update_one(
            {"user_id": user_id},
            {"$pull": {"device_ids": system_id}, "$set": {"last_updated": _now()}},
        )
    logger.info(f"system.user.unbind → user {username} unbound from system {system_id}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
