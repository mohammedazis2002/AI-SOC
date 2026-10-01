from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field

from app.db import get_db
from app.dependencies.auth import get_current_user, require_permission, require_role_names
from app.schemas.alert_feedback import AlertFeedbackSubmit
from app.services.alert_feedback import FEEDBACK_COLLECTION, build_feedback_document, resolve_incident_id_for_alert
from app.services.incidents_service import list_manual_review_queue
from app.services.permissions import get_role_name_for_user
from app.services.processed_alerts import (
    canonical_alert_key,
    count_sidebar_badges,
    display_source,
    doc_to_list_item,
    get_alert_by_id,
    get_unmapped_dlq_doc,
    list_alerts,
    list_unmapped_queue,
    promote_unmapped_to_processed,
    similar_alerts,
    severity_badge,
    status_to_ui,
)
from app.services.review_access import manual_review_tiers_for_role
from app.utils.mongo_json import mongo_to_json

router = APIRouter(prefix='/alerts', tags=['alerts'])


def _resolve_manual_tiers(
    *,
    role_name: str | None,
    is_superadmin: bool,
    tier: str | None,
) -> list[str] | None:
    """Which final_tier values to list. None = all (Admin/superadmin)."""
    allowed = manual_review_tiers_for_role(role_name, is_superadmin)
    if allowed == []:
        return []
    if allowed is None:
        if not tier or tier.lower() in ('all', 'any'):
            return None
        t = tier.lower()
        if t not in ('l1', 'l2', 'l3', 'ir'):
            raise HTTPException(status_code=400, detail='Invalid tier filter')
        return [t]
    if tier:
        t = tier.lower()
        if t not in allowed:
            raise HTTPException(status_code=403, detail='Tier not in your queue')
        return [t]
    return allowed


class UnmappedPromoteBody(BaseModel):
    technique_id: str = Field(..., min_length=1, max_length=64)
    tactic_id: str | None = Field(None, max_length=64)
    tactic_name: str | None = Field(None, max_length=256)
    technique_confidence: float = Field(0.95, ge=0.0, le=1.0)


@router.get('')
async def alerts_list(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    search: Annotated[str | None, Query()] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    status: Annotated[list[str] | None, Query()] = None,
    source: Annotated[str | None, Query(description='Substring match on SIEM source or agent hostname')] = None,
    date_range: Annotated[str | None, Query()] = None,
) -> dict:
    rows, total = await list_alerts(
        db,
        page=page,
        limit=limit,
        search=search,
        severity=severity or [],
        status=status or [],
        source=source,
        date_range=date_range,
    )
    return {'alerts': rows, 'total': total, 'page': page, 'limit': limit}


@router.get('/sidebar-counts')
async def alerts_sidebar_counts(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    user: Annotated[dict, Depends(get_current_user)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
) -> dict:
    role_name = await get_role_name_for_user(db, user)
    new_n, review_badge, unmapped_n = await count_sidebar_badges(
        db,
        role_name=role_name,
        is_superadmin=bool(user.get('is_superadmin')),
    )
    return {
        'newAlertsCount': new_n,
        'reviewQueueCount': review_badge,
        'unmappedCount': unmapped_n,
    }


@router.get('/review-queue/manual')
async def review_queue_manual(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    user: Annotated[dict, Depends(get_current_user)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    search: Annotated[str | None, Query()] = None,
    tier: Annotated[str | None, Query(description='l1|l2|l3|ir — Admin filter; analysts use their default scope')] = None,
) -> dict:
    """MANUAL_REVIEW rows from Mongo `incidents` (agentic reporting), scoped by role."""
    role_name = await get_role_name_for_user(db, user)
    try:
        tiers = _resolve_manual_tiers(
            role_name=role_name,
            is_superadmin=bool(user.get('is_superadmin')),
            tier=tier,
        )
    except HTTPException:
        raise
    rows, total = await list_manual_review_queue(db, tiers=tiers, page=page, limit=limit, search=search)
    return {'alerts': rows, 'total': total, 'page': page, 'limit': limit, 'queue': 'manual_review'}


@router.get('/review-queue/unmapped')
async def review_queue_unmapped(
    _: Annotated[None, Depends(require_role_names({'Admin', 'Engineer'}))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    search: Annotated[str | None, Query()] = None,
) -> dict:
    rows, total = await list_unmapped_queue(db, page=page, limit=limit, search=search)
    return {'alerts': rows, 'total': total, 'page': page, 'limit': limit, 'queue': 'unmapped'}


@router.get('/unmapped/{alert_id}')
async def unmapped_dlq_detail(
    _: Annotated[None, Depends(require_role_names({'Admin', 'Engineer'}))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    alert_id: str,
) -> dict:
    doc = await get_unmapped_dlq_doc(db, alert_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Unmapped alert not found')
    doc.pop('_id', None)
    return {'unmapped': mongo_to_json(doc)}


@router.post('/unmapped/{alert_id}/promote')
async def unmapped_promote(
    body: UnmappedPromoteBody,
    _: Annotated[None, Depends(require_role_names({'Admin', 'Engineer'}))],
    user: Annotated[dict, Depends(get_current_user)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    alert_id: str,
) -> dict:
    analyst = user.get('email') or user.get('name') or str(user.get('_id', ''))
    ok, err = await promote_unmapped_to_processed(
        db,
        alert_id,
        technique_id=body.technique_id,
        tactic_id=body.tactic_id,
        tactic_name=body.tactic_name,
        technique_confidence=body.technique_confidence,
        analyst_label=analyst,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err or 'Promote failed')
    return {'ok': True, 'alert_id': alert_id}


@router.get('/{alert_id}/similar')
async def alert_similar(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    alert_id: str,
    limit: Annotated[int, Query(ge=1, le=20)] = 6,
) -> dict:
    rows = await similar_alerts(db, alert_id, limit=limit)
    return {'alerts': rows}


@router.get('/{alert_id}/feedback')
async def alert_feedback_status(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    alert_id: str,
) -> dict:
    doc = await get_alert_by_id(db, alert_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Alert not found')
    incident_id, _ = await resolve_incident_id_for_alert(db, doc)
    existing = await db[FEEDBACK_COLLECTION].find_one({'incident_id': incident_id}, {'_id': 1})
    return {
        'submitted': existing is not None,
        'feedback_id': str(existing['_id']) if existing else None,
        'incident_id': incident_id,
    }


@router.post('/{alert_id}/feedback', status_code=status.HTTP_201_CREATED)
async def alert_submit_feedback(
    body: AlertFeedbackSubmit,
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    user: Annotated[dict, Depends(get_current_user)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    alert_id: str,
) -> dict:
    doc = await get_alert_by_id(db, alert_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Alert not found')
    analyst_id = str(user.get('email') or user.get('name') or user.get('_id') or 'unknown')
    feedback_doc = await build_feedback_document(db, doc, body, analyst_id)
    inc_id = feedback_doc['incident_id']
    existing = await db[FEEDBACK_COLLECTION].find_one({'incident_id': inc_id})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'Feedback already exists for this incident ({inc_id})',
        )
    result = await db[FEEDBACK_COLLECTION].insert_one(feedback_doc)
    return {
        'status': 'success',
        'feedback_id': str(result.inserted_id),
        'incident_id': inc_id,
        'message': f'Feedback recorded for alert {alert_id}',
    }


@router.get('/{alert_id}')
async def alert_detail(
    _: Annotated[None, Depends(require_permission('dashboard_access'))],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_db)],
    alert_id: str,
) -> dict:
    doc = await get_alert_by_id(db, alert_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Alert not found')
    raw = mongo_to_json(doc)
    finding = doc.get('finding') or {}
    desc = finding.get('title') or finding.get('desc') or doc.get('alert_id')
    return {
        'summary': {
            'id': canonical_alert_key(doc),
            'severity': severity_badge(doc.get('severity_id')),
            'severity_id': doc.get('severity_id'),
            'severity_label': doc.get('severity'),
            'status': status_to_ui(doc.get('status')),
            'description': str(desc)[:2000],
            'display_source': display_source(doc),
            'siem_source': doc.get('siem_source'),
            'timestamp': mongo_to_json(doc.get('time') or doc.get('ingestion_timestamp')),
            'ingestion_timestamp': mongo_to_json(doc.get('ingestion_timestamp')),
            'processed_at': mongo_to_json(doc.get('processed_at')),
            'processing_status': doc.get('processing_status'),
            'category_name': doc.get('category_name'),
            'class_name': doc.get('class_name'),
            'activity_name': doc.get('activity_name'),
            'source_alert_id': doc.get('source_alert_id'),
        },
        'endpoints': {
            'src': mongo_to_json(doc.get('src_endpoint')),
            'dst': mongo_to_json(doc.get('dst_endpoint')),
        },
        'asset': mongo_to_json(doc.get('asset_meta')),
        'asset_risk': mongo_to_json(doc.get('asset_risk')),
        'finding': mongo_to_json(doc.get('finding')),
        'file': mongo_to_json(doc.get('file')),
        'enrichments': mongo_to_json(doc.get('enrichments')),
        'correlation': mongo_to_json(doc.get('correlation')),
        'metadata': mongo_to_json(doc.get('metadata')),
        'unmapped': mongo_to_json(doc.get('unmapped')),
        'raw_data': doc.get('raw_data') if isinstance(doc.get('raw_data'), str) else None,
        'list_row': doc_to_list_item(doc),
        'raw': raw,
    }
