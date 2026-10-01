from typing import Annotated

from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db import get_db
from app.dependencies.auth import require_role_names
from app.services.system_health import build_system_health

router = APIRouter(prefix='/system', tags=['system'])


@router.get('/health')
async def system_health(
    _: Annotated[None, Depends(require_role_names({'Admin', 'Engineer'}))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
) -> dict:
    return await build_system_health(db)
