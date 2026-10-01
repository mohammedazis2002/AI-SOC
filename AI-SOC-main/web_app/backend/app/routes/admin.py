from datetime import datetime, timezone
from typing import Annotated, Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db import get_db
from app.dependencies.auth import get_current_user, require_permission
from app.models import COLLECTION_ROLES, COLLECTION_USERS
from app.schemas.role import RolePermissions, RolePublic
from app.schemas.user import AssignRoleRequest, UserPendingItem, UserPermissionsPublic, UserPublic
from app.services.audit import write_audit
from app.services.permissions import get_role_name_for_user, load_user_permissions
from app.utils.objectid import oid_str, parse_oid

router = APIRouter(prefix="/admin", tags=["admin"])


async def _user_public(db: AsyncIOMotorDatabase, doc: dict[str, Any]) -> UserPublic:
    role_name = await get_role_name_for_user(db, doc)
    perms = await load_user_permissions(db, doc)
    return UserPublic(
        id=oid_str(doc["_id"]),
        name=doc["name"],
        email=doc["email"],
        status=doc["status"],
        role_id=oid_str(doc["role_id"]) if doc.get("role_id") else None,
        role_name=role_name,
        is_superadmin=bool(doc.get("is_superadmin")),
        created_at=doc["created_at"],
        updated_at=doc["updated_at"],
        permissions=UserPermissionsPublic(
            user_management=perms["user_management"],
            dashboard_access=perms["dashboard_access"],
            backend_access=perms["backend_access"],
        ),
    )


@router.get("/roles", response_model=list[RolePublic])
async def list_roles(
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("user_management"))],
) -> list[RolePublic]:
    cursor = db[COLLECTION_ROLES].find({}).sort("name", 1)
    out: list[RolePublic] = []
    async for doc in cursor:
        p = doc.get("permissions") or {}
        out.append(
            RolePublic(
                id=oid_str(doc["_id"]),
                name=doc["name"],
                permissions=RolePermissions(
                    user_management=bool(p.get("user_management")),
                    dashboard_access=bool(p.get("dashboard_access")),
                    backend_access=bool(p.get("backend_access")),
                ),
            )
        )
    return out


@router.get("/users", response_model=list[UserPublic])
async def list_users(
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("user_management"))],
) -> list[UserPublic]:
    cursor = db[COLLECTION_USERS].find({}).sort("name", 1)
    out: list[UserPublic] = []
    async for doc in cursor:
        out.append(await _user_public(db, doc))
    return out


@router.get("/users/pending", response_model=list[UserPendingItem])
async def list_pending(
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("user_management"))],
) -> list[UserPendingItem]:
    cursor = db[COLLECTION_USERS].find({"status": "pending"}).sort("created_at", 1)
    out: list[UserPendingItem] = []
    async for doc in cursor:
        out.append(
            UserPendingItem(
                id=oid_str(doc["_id"]),
                name=doc["name"],
                email=doc["email"],
                status=doc["status"],
                created_at=doc["created_at"],
            )
        )
    return out


@router.post("/users/{user_id}/approve", response_model=UserPublic)
async def approve_user(
    user_id: str,
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("user_management"))],
    current: Annotated[dict[str, Any], Depends(get_current_user)],
) -> UserPublic:
    try:
        oid = parse_oid(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user id")

    target = await db[COLLECTION_USERS].find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.get("is_superadmin"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot modify superadmin")

    now = datetime.now(timezone.utc)
    await db[COLLECTION_USERS].update_one(
        {"_id": oid},
        {"$set": {"status": "active", "updated_at": now}},
    )
    updated = await db[COLLECTION_USERS].find_one({"_id": oid})
    assert updated

    await write_audit(
        db,
        action="user_approved",
        actor_id=oid_str(current["_id"]),
        target_user_id=user_id,
        details={},
    )

    return await _user_public(db, updated)


@router.post("/users/{user_id}/reject", response_model=UserPublic)
async def reject_user(
    user_id: str,
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("user_management"))],
    current: Annotated[dict[str, Any], Depends(get_current_user)],
) -> UserPublic:
    try:
        oid = parse_oid(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user id")

    target = await db[COLLECTION_USERS].find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.get("is_superadmin"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot reject superadmin")

    now = datetime.now(timezone.utc)
    await db[COLLECTION_USERS].update_one(
        {"_id": oid},
        {"$set": {"status": "rejected", "updated_at": now}},
    )
    updated = await db[COLLECTION_USERS].find_one({"_id": oid})
    assert updated

    await write_audit(
        db,
        action="user_rejected",
        actor_id=oid_str(current["_id"]),
        target_user_id=user_id,
        details={},
    )

    return await _user_public(db, updated)


@router.post("/users/{user_id}/revoke", response_model=UserPublic)
async def revoke_user_access(
    user_id: str,
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("user_management"))],
    current: Annotated[dict[str, Any], Depends(get_current_user)],
) -> UserPublic:
    try:
        oid = parse_oid(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user id")

    if oid == current["_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot revoke your own access",
        )

    target = await db[COLLECTION_USERS].find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.get("is_superadmin"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot revoke superadmin access")

    if target.get("status") != "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only active accounts can be revoked",
        )

    now = datetime.now(timezone.utc)
    await db[COLLECTION_USERS].update_one(
        {"_id": oid},
        {"$set": {"status": "disabled", "updated_at": now}},
    )
    updated = await db[COLLECTION_USERS].find_one({"_id": oid})
    assert updated

    await write_audit(
        db,
        action="user_access_revoked",
        actor_id=oid_str(current["_id"]),
        target_user_id=user_id,
        details={},
    )

    return await _user_public(db, updated)


@router.post("/users/{user_id}/restore", response_model=UserPublic)
async def restore_user_access(
    user_id: str,
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("user_management"))],
    current: Annotated[dict[str, Any], Depends(get_current_user)],
) -> UserPublic:
    try:
        oid = parse_oid(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user id")

    target = await db[COLLECTION_USERS].find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.get("is_superadmin"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot modify superadmin")

    if target.get("status") != "disabled":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only disabled accounts can be restored",
        )

    now = datetime.now(timezone.utc)
    await db[COLLECTION_USERS].update_one(
        {"_id": oid},
        {"$set": {"status": "active", "updated_at": now}},
    )
    updated = await db[COLLECTION_USERS].find_one({"_id": oid})
    assert updated

    await write_audit(
        db,
        action="user_access_restored",
        actor_id=oid_str(current["_id"]),
        target_user_id=user_id,
        details={},
    )

    return await _user_public(db, updated)


@router.post("/users/{user_id}/assign-role", response_model=UserPublic)
async def assign_role(
    user_id: str,
    body: AssignRoleRequest,
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("user_management"))],
    current: Annotated[dict[str, Any], Depends(get_current_user)],
) -> UserPublic:
    try:
        oid = parse_oid(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user id")

    try:
        role_oid = ObjectId(body.role_id)
    except InvalidId:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role id")

    target = await db[COLLECTION_USERS].find_one({"_id": oid})
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.get("is_superadmin"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot change superadmin role")

    role = await db[COLLECTION_ROLES].find_one({"_id": role_oid})
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    now = datetime.now(timezone.utc)
    await db[COLLECTION_USERS].update_one(
        {"_id": oid},
        {"$set": {"role_id": role_oid, "updated_at": now}},
    )
    updated = await db[COLLECTION_USERS].find_one({"_id": oid})
    assert updated

    await write_audit(
        db,
        action="role_assigned",
        actor_id=oid_str(current["_id"]),
        target_user_id=user_id,
        details={"role_id": body.role_id, "role_name": role.get("name")},
    )

    return await _user_public(db, updated)
