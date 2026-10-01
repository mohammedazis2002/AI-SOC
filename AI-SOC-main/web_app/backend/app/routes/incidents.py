from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field

from app.db import get_db
from app.dependencies.auth import get_current_user, require_permission
from app.services.incidents_service import (
    escalate_incident_tier,
    get_incident_by_alert_id,
    get_incident_by_id,
    update_incident_alert_and_meta,
)
from app.services.permissions import get_role_name_for_user
from app.services.review_access import user_may_escalate_incident
from app.utils.mongo_json import mongo_to_json

router = APIRouter(prefix='/incidents', tags=['incidents'])


class IncidentPatchBody(BaseModel):
    alert_patch: dict[str, Any] | None = None
    analyst_notes: str | None = Field(None, max_length=20_000)


class EscalateBody(BaseModel):
    to_tier: str = Field(..., description='l2 | l3 | ir')


@router.get('/by-alert/{alert_id}')
async def incident_by_alert(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    alert_id: str,
) -> dict:
    doc = await get_incident_by_alert_id(db, alert_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='No incident for this alert')
    doc.pop('_id', None)
    return {'incident': mongo_to_json(doc)}


@router.get('/{incident_id}')
async def incident_detail(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    incident_id: str,
) -> dict:
    doc = await get_incident_by_id(db, incident_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Incident not found')
    doc.pop('_id', None)
    return {'incident': mongo_to_json(doc)}


@router.patch('/{incident_id}')
async def incident_patch(
    body: IncidentPatchBody,
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    user: Annotated[dict, Depends(get_current_user)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    incident_id: str,
) -> dict:
    updated = await update_incident_alert_and_meta(
        db,
        incident_id,
        alert_patch=body.alert_patch,
        analyst_notes=body.analyst_notes,
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Incident not found')
    updated.pop('_id', None)
    return {'incident': mongo_to_json(updated)}


@router.post('/{incident_id}/escalate')
async def incident_escalate(
    body: EscalateBody,
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    user: Annotated[dict, Depends(get_current_user)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    incident_id: str,
) -> dict:
    doc = await get_incident_by_id(db, incident_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Incident not found')
    role_name = await get_role_name_for_user(db, user)
    ct = str(doc.get('final_tier') or '')
    if not user_may_escalate_incident(role_name, bool(user.get('is_superadmin')), ct):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Cannot escalate this incident')
    updated = await escalate_incident_tier(db, incident_id, to_tier=body.to_tier)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Invalid escalation for current tier',
        )
    updated.pop('_id', None)
    return {'incident': mongo_to_json(updated)}
