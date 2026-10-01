from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models import COLLECTION_ROLES, COLLECTION_USERS

ROLE_DEFINITIONS: list[dict] = [
    {
        "name": "Admin",
        "permissions": {
            "user_management": True,
            "dashboard_access": True,
            "backend_access": True,
        },
    },
    {
        "name": "L1",
        "permissions": {
            "user_management": False,
            "dashboard_access": True,
            "backend_access": False,
        },
    },
    {
        "name": "L2",
        "permissions": {
            "user_management": False,
            "dashboard_access": True,
            "backend_access": True,
        },
    },
    {
        "name": "L3",
        "permissions": {
            "user_management": False,
            "dashboard_access": True,
            "backend_access": True,
        },
    },
    {
        "name": "Engineer",
        "permissions": {
            "user_management": False,
            "dashboard_access": True,
            "backend_access": True,
        },
    },
]


async def seed_roles_if_empty(db: AsyncIOMotorDatabase) -> int:
    count = await db[COLLECTION_ROLES].count_documents({})
    if count > 0:
        return 0
    inserted = 0
    for role in ROLE_DEFINITIONS:
        await db[COLLECTION_ROLES].insert_one(role)
        inserted += 1
    return inserted


async def retire_l4_role_if_present(db: AsyncIOMotorDatabase) -> None:
    """Remove deprecated L4 role: reassign users to L3, then delete the role document."""
    l4 = await db[COLLECTION_ROLES].find_one({"name": "L4"})
    if not l4:
        return
    l3 = await db[COLLECTION_ROLES].find_one({"name": "L3"})
    rid_l4 = l4["_id"]
    if l3:
        await db[COLLECTION_USERS].update_many({"role_id": rid_l4}, {"$set": {"role_id": l3["_id"]}})
    else:
        await db[COLLECTION_USERS].update_many({"role_id": rid_l4}, {"$set": {"role_id": None}})
    await db[COLLECTION_ROLES].delete_one({"_id": rid_l4})
