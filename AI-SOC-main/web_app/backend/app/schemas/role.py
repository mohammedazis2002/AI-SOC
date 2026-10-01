from pydantic import BaseModel


class RolePermissions(BaseModel):
    user_management: bool = False
    dashboard_access: bool = False
    backend_access: bool = False


class RolePublic(BaseModel):
    id: str
    name: str
    permissions: RolePermissions
