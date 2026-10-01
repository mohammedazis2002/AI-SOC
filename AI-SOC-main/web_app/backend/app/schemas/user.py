from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserPermissionsPublic(BaseModel):
    user_management: bool = False
    dashboard_access: bool = False
    backend_access: bool = False


class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    status: str
    role_id: str | None
    role_name: str | None = None
    is_superadmin: bool
    created_at: datetime
    updated_at: datetime
    permissions: UserPermissionsPublic | None = None


class UserPendingItem(BaseModel):
    id: str
    name: str
    email: EmailStr
    status: str
    created_at: datetime


class AssignRoleRequest(BaseModel):
    role_id: str = Field(..., min_length=1)
