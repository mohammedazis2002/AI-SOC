from datetime import datetime, timezone
from typing import Annotated, Any

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.security import create_access_token, hash_password, verify_password
from app.db import get_db
from app.dependencies.auth import get_current_user
from app.models import COLLECTION_USERS
from app.schemas.auth import LoginRequest, RegisterRequest, RegisterResponse, TokenResponse
from app.schemas.user import UserPermissionsPublic, UserPublic
from app.services.permissions import get_role_by_name, get_role_name_for_user, load_user_permissions
from app.services.seed_roles import seed_roles_if_empty
from app.utils.objectid import oid_str

router = APIRouter(tags=["auth"])


@router.post("/register", response_model=RegisterResponse)
async def register(body: RegisterRequest, db: Annotated[AsyncIOMotorDatabase, Depends(get_db)]) -> RegisterResponse:
    await seed_roles_if_empty(db)
    email_norm = body.email.lower().strip()

    existing = await db[COLLECTION_USERS].find_one({"email": email_norm})
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    total = await db[COLLECTION_USERS].count_documents({})
    now = datetime.now(timezone.utc)
    hashed = hash_password(body.password)

    if total == 0:
        admin_role = await get_role_by_name(db, "Admin")
        if not admin_role:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Admin role missing; run seed",
            )
        doc: dict[str, Any] = {
            "name": body.name.strip(),
            "email": email_norm,
            "hashed_password": hashed,
            "role_id": admin_role["_id"],
            "status": "active",
            "is_superadmin": True,
            "created_at": now,
            "updated_at": now,
        }
        result = await db[COLLECTION_USERS].insert_one(doc)
        uid = oid_str(result.inserted_id)
        return RegisterResponse(
            id=uid,
            email=email_norm,
            name=doc["name"],
            status="active",
            message="Registered as superadmin; you may log in immediately.",
        )

    doc = {
        "name": body.name.strip(),
        "email": email_norm,
        "hashed_password": hashed,
        "role_id": None,
        "status": "pending",
        "is_superadmin": False,
        "created_at": now,
        "updated_at": now,
    }
    result = await db[COLLECTION_USERS].insert_one(doc)
    uid = oid_str(result.inserted_id)
    return RegisterResponse(
        id=uid,
        email=email_norm,
        name=doc["name"],
        status="pending",
        message="Registration received; awaiting administrator approval.",
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: Annotated[AsyncIOMotorDatabase, Depends(get_db)]) -> TokenResponse:
    email_norm = body.email.lower().strip()
    user = await db[COLLECTION_USERS].find_one({"email": email_norm})
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if user.get("status") != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not active",
        )

    token = create_access_token(oid_str(user["_id"]))
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserPublic)
async def me(
    current: Annotated[dict[str, Any], Depends(get_current_user)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
) -> UserPublic:
    u = current
    role_name = await get_role_name_for_user(db, u)
    perms = await load_user_permissions(db, u)
    return UserPublic(
        id=oid_str(u["_id"]),
        name=u["name"],
        email=u["email"],
        status=u["status"],
        role_id=oid_str(u["role_id"]) if u.get("role_id") else None,
        role_name=role_name,
        is_superadmin=bool(u.get("is_superadmin")),
        created_at=u["created_at"],
        updated_at=u["updated_at"],
        permissions=UserPermissionsPublic(
            user_management=perms["user_management"],
            dashboard_access=perms["dashboard_access"],
            backend_access=perms["backend_access"],
        ),
    )
