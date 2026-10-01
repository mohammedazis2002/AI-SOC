from typing import Annotated

from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db import get_db
from app.dependencies.auth import require_permission
from app.services.analytics_stats import build_analytics

router = APIRouter(prefix='/analytics', tags=['analytics'])


@router.get('/summary')
async def analytics_summary(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    days: Annotated[int, Query(ge=1, le=90)] = 30,
) -> dict:
    return await build_analytics(db, days=days)
