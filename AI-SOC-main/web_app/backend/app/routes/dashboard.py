from typing import Annotated

from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db import get_db
from app.dependencies.auth import require_permission
from app.services.dashboard_stats import build_dashboard_summary

router = APIRouter(prefix='/dashboard', tags=['dashboard'])


@router.get('/summary')
async def dashboard_summary(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    days: Annotated[int, Query(ge=1, le=90)] = 14,
) -> dict:
    return await build_dashboard_summary(db, days=days)
