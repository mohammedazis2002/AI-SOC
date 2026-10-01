from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db import get_db
from app.core.security import verify_token
from app.models import COLLECTION_ROLES, COLLECTION_USERS
from app.services.permissions import load_user_permissions

security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user_id = verify_token(credentials.credentials)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    from bson import ObjectId
    from bson.errors import InvalidId

    try:
        oid = ObjectId(user_id)
    except InvalidId:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid subject")

    user = await db[COLLECTION_USERS].find_one({"_id": oid})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if user.get("status") != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not active")
    return user


async def get_user_permissions(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
) -> dict[str, bool]:
    return await load_user_permissions(db, user)


def require_permission(permission_name: str) -> Callable[..., Any]:
    async def checker(
        permissions: Annotated[dict[str, bool], Depends(get_user_permissions)],
    ) -> None:
        if not permissions.get(permission_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission_name}",
            )

    return checker


def require_role_names(allowed: set[str]) -> Callable[..., Any]:
    async def checker(user: Annotated[dict[str, Any], Depends(get_current_user)], db: Annotated[AsyncIOMotorDatabase, Depends(get_db)]) -> None:
        if user.get("is_superadmin"):
            return
        role_id = user.get("role_id")
        if not role_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Role required")
        role = await db[COLLECTION_ROLES].find_one({"_id": role_id}, {"name": 1})
        name = role.get("name") if role else None
        if name not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    return checker
