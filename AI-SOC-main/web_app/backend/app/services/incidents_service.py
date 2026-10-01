"""Mongo `incidents` collection — agentic pipeline outcomes (e.g. MANUAL_REVIEW)."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.services.processed_alerts import severity_badge
from app.services.review_access import INCIDENTS_COLLECTION, allowed_escalation_targets

_MANUAL_DECISION = 'MANUAL_REVIEW'


def _alert_from_incident(doc: dict[str, Any]) -> dict[str, Any]:
    return doc.get('alert') if isinstance(doc.get('alert'), dict) else {}


def incident_to_queue_item(doc: dict[str, Any]) -> dict[str, Any]:
    alert = _alert_from_incident(doc)
    finding = alert.get('finding') or {}
    desc = finding.get('title') or finding.get('desc') or alert.get('alert_id') or doc.get('incident_id')
    src_ep = alert.get('src_endpoint') or {}
    src_ip = str(src_ep.get('ip') or '') if isinstance(src_ep, dict) else ''
    ts = doc.get('execution_ended') or doc.get('created_at') or doc.get('updated_at')
    ts_iso = ts.isoformat() if hasattr(ts, 'isoformat') else None
    return {
        'id': doc.get('incident_id'),
        'kind': 'manual_review',
        'queue_kind': 'manual_review',
        'incident_id': doc.get('incident_id'),
        'alert_id': alert.get('alert_id'),
        'severity': severity_badge(alert.get('severity_id')),
        'description': str(desc)[:500],
        'source_siem': str(alert.get('siem_source') or 'unknown'),
        'source_ip': src_ip or None,
        'dest_ip': None,
        'correlation_group': (alert.get('correlation') or {}).get('incident_id')
        if isinstance(alert.get('correlation'), dict)
        else None,
        'confidence': 0.0,
        'final_tier': doc.get('final_tier'),
        'priority': doc.get('priority'),
        'decision_reason': doc.get('decision_reason'),
        'timestamp': ts_iso,
        'mttd_minutes': None,
        'mttr_minutes': None,
    }


async def count_manual_review(
    db: AsyncIOMotorDatabase,
    *,
    tiers: list[str] | None,
) -> int:
    coll = db[INCIDENTS_COLLECTION]
    match: dict[str, Any] = {'decision': _MANUAL_DECISION}
    if tiers is not None:
        if not tiers:
            return 0
        match['final_tier'] = {'$in': tiers}
    return await coll.count_documents(match)


async def list_manual_review_queue(
    db: AsyncIOMotorDatabase,
    *,
    tiers: list[str] | None,
    page: int = 1,
    limit: int = 50,
    search: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    coll = db[INCIDENTS_COLLECTION]
    match: dict[str, Any] = {'decision': _MANUAL_DECISION}
    if tiers is not None:
        if not tiers:
            return [], 0
        match['final_tier'] = {'$in': tiers}
    if search and search.strip():
        q = search.strip()
        rx = {'$regex': q, '$options': 'i'}
        match = {
            '$and': [
                match,
                {
                    '$or': [
                        {'incident_id': rx},
                        {'alert.alert_id': rx},
                        {'alert.finding.title': rx},
                        {'alert.finding.desc': rx},
                    ]
                },
            ]
        }
    total = await coll.count_documents(match)
    skip = max(0, (page - 1) * limit)
    cursor = coll.find(match).sort([('execution_ended', -1), ('created_at', -1)]).skip(skip).limit(limit)
    rows: list[dict[str, Any]] = []
    async for doc in cursor:
        doc.pop('_id', None)
        rows.append(incident_to_queue_item(doc))
    return rows, total


async def get_incident_by_id(db: AsyncIOMotorDatabase, incident_id: str) -> dict[str, Any] | None:
    coll = db[INCIDENTS_COLLECTION]
    return await coll.find_one({'incident_id': incident_id})


async def get_incident_by_alert_id(db: AsyncIOMotorDatabase, alert_id: str) -> dict[str, Any] | None:
    coll = db[INCIDENTS_COLLECTION]
    return await coll.find_one({'alert.alert_id': alert_id})


def deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(base)
    for k, v in patch.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v) if isinstance(v, dict) else v
    return out


async def update_incident_alert_and_meta(
    db: AsyncIOMotorDatabase,
    incident_id: str,
    *,
    alert_patch: dict[str, Any] | None,
    analyst_notes: str | None,
) -> dict[str, Any] | None:
    coll = db[INCIDENTS_COLLECTION]
    doc = await coll.find_one({'incident_id': incident_id})
    if not doc:
        return None
    now = datetime.now(UTC)
    set_fields: dict[str, Any] = {'updated_at': now}
    if analyst_notes is not None:
        set_fields['analyst_notes'] = analyst_notes
    if alert_patch is not None:
        alert = _alert_from_incident(doc)
        merged = deep_merge(alert, alert_patch)
        set_fields['alert'] = merged
    await coll.update_one({'incident_id': incident_id}, {'$set': set_fields})
    return await coll.find_one({'incident_id': incident_id})


async def escalate_incident_tier(
    db: AsyncIOMotorDatabase,
    incident_id: str,
    *,
    to_tier: str,
) -> dict[str, Any] | None:
    coll = db[INCIDENTS_COLLECTION]
    doc = await coll.find_one({'incident_id': incident_id})
    if not doc:
        return None
    from_tier = str(doc.get('final_tier') or '').lower()
    to = to_tier.lower()

    if to not in allowed_escalation_targets(from_tier):
        return None
    now = datetime.now(UTC).isoformat()
    history = doc.get('escalation_history')
    if not isinstance(history, list):
        history = []
    history.append({'from_tier': from_tier, 'to_tier': to, 'at': now})
    await coll.update_one(
        {'incident_id': incident_id},
        {
            '$set': {
                'final_tier': to,
                'updated_at': datetime.now(UTC),
                'escalation_history': history,
            }
        },
    )
    return await coll.find_one({'incident_id': incident_id})
