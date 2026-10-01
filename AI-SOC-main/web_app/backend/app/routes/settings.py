from typing import Annotated

from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db import get_db
from app.dependencies.auth import require_permission
from app.services.siem_connections import build_siem_connections

router = APIRouter(prefix='/settings', tags=['settings'])


@router.get('/siem-connections')
async def siem_connections(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
) -> dict:
    return await build_siem_connections(db)
