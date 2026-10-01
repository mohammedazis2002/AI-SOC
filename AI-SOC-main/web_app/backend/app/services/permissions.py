from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models import COLLECTION_ROLES, COLLECTION_USERS

ALL_PERMISSION_KEYS = ("user_management", "dashboard_access", "backend_access")


async def load_user_permissions(db: AsyncIOMotorDatabase, user: dict[str, Any]) -> dict[str, bool]:
    if user.get("is_superadmin"):
        return {k: True for k in ALL_PERMISSION_KEYS}

    role_id = user.get("role_id")
    if not role_id:
        return {k: False for k in ALL_PERMISSION_KEYS}

    role = await db[COLLECTION_ROLES].find_one({"_id": role_id})
    if not role:
        return {k: False for k in ALL_PERMISSION_KEYS}

    perms = role.get("permissions") or {}
    return {
        "user_management": bool(perms.get("user_management")),
        "dashboard_access": bool(perms.get("dashboard_access")),
        "backend_access": bool(perms.get("backend_access")),
    }


async def get_role_by_name(db: AsyncIOMotorDatabase, name: str) -> dict[str, Any] | None:
    return await db[COLLECTION_ROLES].find_one({"name": name})


async def get_role_name_for_user(db: AsyncIOMotorDatabase, user: dict[str, Any]) -> str | None:
    if user.get("is_superadmin"):
        return "Superadmin"
    role_id = user.get("role_id")
    if not role_id:
        return None
    role = await db[COLLECTION_ROLES].find_one({"_id": role_id}, {"name": 1})
    if not role:
        return None
    return role.get("name")
