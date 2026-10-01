"""Query helpers for `alerts_processed` collection."""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

COLLECTION = 'alerts_processed'
UNMAPPED_COLLECTION = 'unmapped_alerts'


def canonical_alert_key(doc: dict[str, Any]) -> str:
    """Stable id for API URLs: matches list row, detail summary, and feedback paths."""
    for k in ('alert_id', 'source_alert_id'):
        v = doc.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    oid = doc.get('_id')
    if oid is not None:
        return str(oid)
    return ''

_SEV_TO_BADGE = {
    5: 'CRITICAL',
    4: 'HIGH',
    3: 'MEDIUM',
    2: 'LOW',
    1: 'INFO',
    0: 'INFO',
}


def severity_badge(severity_id: Any) -> str:
    try:
        return _SEV_TO_BADGE.get(int(severity_id), 'INFO')
    except (TypeError, ValueError):
        return 'INFO'


def display_source(doc: dict[str, Any]) -> str:
    raw = (doc.get('siem_source') or '').strip()
    if raw and raw.lower() != 'unknown':
        return raw
    ep = doc.get('src_endpoint') or {}
    host = ep.get('hostname') if isinstance(ep, dict) else None
    if host:
        return str(host).strip()
    am = doc.get('asset_meta') or {}
    if isinstance(am, dict) and am.get('hostname'):
        return str(am.get('hostname')).strip()
    return 'Unknown'


def status_to_ui(db_status: Any) -> str:
    if not db_status:
        return 'new'
    s = str(db_status).lower().replace(' ', '_')
    m = {
        'open': 'new',
        'new': 'new',
        'in_progress': 'in_review',
        'in_review': 'in_review',
        'resolved': 'resolved',
        'false_positive': 'false_positive',
        'escalated': 'escalated',
        'closed': 'resolved',
    }
    return m.get(s, 'new')


def ui_status_to_db_match(ui: list[str]) -> list[dict[str, Any]]:
    """OR of possible DB status values for selected UI filters."""
    if not ui:
        return []
    clauses: list[dict[str, Any]] = []
    for u in ui:
        if u == 'new':
            clauses.append({'status': {'$in': ['open', 'Open', 'new', 'New']}})
        elif u == 'in_review':
            clauses.append({'status': {'$in': ['in_review', 'in progress', 'In Progress']}})
        elif u == 'resolved':
            clauses.append({'status': {'$in': ['resolved', 'Resolved', 'closed', 'Closed']}})
        elif u == 'false_positive':
            clauses.append({'status': {'$in': ['false_positive', 'False Positive']}})
        elif u == 'escalated':
            clauses.append({'status': {'$in': ['escalated', 'Escalated']}})
    return clauses


def severity_ui_to_ids(labels: list[str]) -> list[int]:
    m = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
    out: list[int] = []
    for L in labels:
        if L in m:
            out.append(m[L])
    return out


def doc_to_list_item(doc: dict[str, Any]) -> dict[str, Any]:
    finding = doc.get('finding') or {}
    desc = finding.get('title') or finding.get('desc') or doc.get('alert_id') or 'Alert'
    src_ep = doc.get('src_endpoint') or {}
    dst_ep = doc.get('dst_endpoint') or {}
    corr = doc.get('correlation') or {}
    incident = corr.get('incident_id') if isinstance(corr, dict) else None
    enrich = doc.get('enrichments') or {}
    ti = enrich.get('threat_intel') if isinstance(enrich, dict) else None
    conf = 0.5
    if isinstance(ti, dict) and ti.get('aggregate_score') is not None:
        try:
            conf = max(0.0, min(1.0, float(ti['aggregate_score'])))
        except (TypeError, ValueError):
            pass

    ts = doc.get('time') or doc.get('ingestion_timestamp')
    ts_iso = ts.isoformat() if hasattr(ts, 'isoformat') else datetime.now(UTC).isoformat()

    mttd: float | None = None
    proc = doc.get('processed_at')
    meta = doc.get('metadata') or {}
    orig = meta.get('original_time') if isinstance(meta, dict) else None
    if hasattr(proc, 'timestamp') and hasattr(orig, 'timestamp'):
        try:
            mttd = max(0.0, (proc - orig).total_seconds() / 60.0)
        except Exception:
            pass

    return {
        'id': canonical_alert_key(doc),
        'severity': severity_badge(doc.get('severity_id')),
        'description': str(desc)[:500],
        'source_siem': display_source(doc),
        'source_ip': str(src_ep.get('ip') or '') if isinstance(src_ep, dict) else '',
        'dest_ip': str(dst_ep.get('ip') or '') if isinstance(dst_ep, dict) and dst_ep.get('ip') else None,
        'correlation_group': str(incident) if incident else None,
        'confidence': conf,
        'status': status_to_ui(doc.get('status')),
        'mttd_minutes': round(mttd, 1) if mttd is not None else None,
        'mttr_minutes': None,
        'timestamp': ts_iso,
    }


def build_list_match(
    *,
    search: str | None,
    severity: list[str] | None,
    status: list[str] | None,
    source: str | None,
    date_range: str | None,
) -> dict[str, Any]:
    parts: list[dict[str, Any]] = []

    if search and search.strip():
        q = search.strip()
        parts.append(
            {
                '$or': [
                    {'alert_id': {'$regex': q, '$options': 'i'}},
                    {'finding.title': {'$regex': q, '$options': 'i'}},
                    {'finding.desc': {'$regex': q, '$options': 'i'}},
                    {'src_endpoint.ip': {'$regex': q, '$options': 'i'}},
                    {'dst_endpoint.ip': {'$regex': q, '$options': 'i'}},
                ]
            }
        )

    if severity:
        ids = severity_ui_to_ids(severity)
        if ids:
            parts.append({'severity_id': {'$in': ids}})

    if status:
        sc = ui_status_to_db_match(status)
        if sc:
            parts.append({'$or': sc})

    if source and source.strip():
        s = source.strip()
        parts.append(
            {
                '$or': [
                    {'siem_source': {'$regex': s, '$options': 'i'}},
                    {'src_endpoint.hostname': {'$regex': s, '$options': 'i'}},
                    {'asset_meta.hostname': {'$regex': s, '$options': 'i'}},
                ]
            }
        )

    now = datetime.now(UTC)
    dr = (date_range or '24h').lower()
    if dr == '1h':
        cutoff = now - timedelta(hours=1)
    elif dr == '24h':
        cutoff = now - timedelta(hours=24)
    elif dr == '7d':
        cutoff = now - timedelta(days=7)
    else:
        # custom / unknown → no time window filter
        cutoff = None
    if cutoff is not None:
        parts.append(
            {
                '$or': [
                    {'time': {'$gte': cutoff}},
                    {'ingestion_timestamp': {'$gte': cutoff}},
                ]
            }
        )

    if not parts:
        return {}
    if len(parts) == 1:
        return parts[0]
    return {'$and': parts}


async def list_alerts(
    db: AsyncIOMotorDatabase,
    *,
    page: int = 1,
    limit: int = 50,
    search: str | None = None,
    severity: list[str] | None = None,
    status: list[str] | None = None,
    source: str | None = None,
    date_range: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    coll = db[COLLECTION]
    match = build_list_match(
        search=search,
        severity=severity or [],
        status=status or [],
        source=source,
        date_range=date_range,
    )
    total = await coll.count_documents(match)
    skip = max(0, (page - 1) * limit)
    cursor = (
        coll.find(match)
        .sort([('ingestion_timestamp', -1), ('time', -1)])
        .skip(skip)
        .limit(limit)
    )
    rows: list[dict[str, Any]] = []
    async for doc in cursor:
        rows.append(doc_to_list_item(doc))
    return rows, total


async def get_alert_by_id(db: AsyncIOMotorDatabase, alert_id: str) -> dict[str, Any] | None:
    if not alert_id or not str(alert_id).strip():
        return None
    aid = str(alert_id).strip()
    coll = db[COLLECTION]
    doc = await coll.find_one({'alert_id': aid})
    if doc is None:
        rx = re.escape(aid)
        doc = await coll.find_one({'alert_id': {'$regex': f'^{rx}$', '$options': 'i'}})
    if doc is None:
        doc = await coll.find_one({'source_alert_id': aid})
    if doc is None:
        rx = re.escape(aid)
        doc = await coll.find_one({'source_alert_id': {'$regex': f'^{rx}$', '$options': 'i'}})
    if doc is None:
        from bson import ObjectId
        from bson.errors import InvalidId

        try:
            doc = await coll.find_one({'_id': ObjectId(aid)})
        except InvalidId:
            pass
    return doc


async def count_sidebar_badges(
    db: AsyncIOMotorDatabase,
    *,
    role_name: str | None,
    is_superadmin: bool,
) -> tuple[int, int, int]:
    """new_open, review_queue_badge (manual-review for role + unmapped if Engineer/Admin), unmapped_count (0 if role cannot see tab)."""
    from app.services.incidents_service import count_manual_review
    from app.services.review_access import can_see_unmapped_tab, manual_review_tiers_for_role

    coll = db[COLLECTION]
    # Keep the sidebar "Alerts" badge consistent with the default Alerts page window (24h).
    # Otherwise users can see a non-zero badge while the Alerts list is empty (due to date_range filtering).
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    new_open = await coll.count_documents(
        {
            '$and': [
                {'status': {'$in': ['open', 'Open', 'new', 'New']}},
                {
                    '$or': [
                        {'time': {'$gte': cutoff}},
                        {'ingestion_timestamp': {'$gte': cutoff}},
                    ]
                },
            ]
        }
    )
    tiers = manual_review_tiers_for_role(role_name, is_superadmin)
    manual = await count_manual_review(db, tiers=tiers)
    unmapped_total = await db[UNMAPPED_COLLECTION].count_documents(
        {'status': {'$in': ['pending_analyst_review', 'pending']}},
    )
    unmapped_for_user = unmapped_total if can_see_unmapped_tab(role_name, is_superadmin) else 0
    badge = manual + unmapped_for_user
    return new_open, badge, unmapped_for_user


def unmapped_dlq_to_list_item(doc: dict[str, Any]) -> dict[str, Any]:
    ulf = doc.get('normalised_ulf') or {}
    finding = ulf.get('finding') or {}
    desc = finding.get('title') or finding.get('desc') or doc.get('alert_id') or 'Unmapped alert'
    mitre = doc.get('mitre_enrichment') or {}
    sev_id = ulf.get('severity_id')
    src_ep = ulf.get('src_endpoint') or {}
    src_ip = str(src_ep.get('ip') or '') if isinstance(src_ep, dict) else ''
    conf = 0.0
    try:
        conf = float(doc.get('technique_confidence') or mitre.get('technique_confidence') or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    return {
        'id': doc.get('alert_id') or str(doc.get('_id')),
        'kind': 'unmapped',
        'queue_kind': 'unmapped',
        'severity': severity_badge(sev_id),
        'description': str(desc)[:500],
        'source_siem': (ulf.get('siem_source') or 'unknown'),
        'source_ip': src_ip,
        'dest_ip': None,
        'correlation_group': None,
        'confidence': max(0.0, min(1.0, conf)),
        'dlq_reason': doc.get('dlq_reason'),
        'mapping_method': mitre.get('mapping_method') or doc.get('mapping_method'),
        'technique_confidence': doc.get('technique_confidence'),
        'queued_at': doc.get('queued_at'),
        'status': doc.get('status') or 'pending',
        'timestamp': doc.get('queued_at'),
        'mttd_minutes': None,
        'mttr_minutes': None,
    }


async def list_unmapped_queue(
    db: AsyncIOMotorDatabase,
    *,
    page: int = 1,
    limit: int = 50,
    search: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """MITRE DLQ documents (normalisation produced no technique_id)."""
    coll = db[UNMAPPED_COLLECTION]
    match: dict[str, Any] = {'status': {'$in': ['pending_analyst_review', 'pending']}}
    if search and search.strip():
        q = search.strip()
        match = {
            '$and': [
                match,
                {
                    '$or': [
                        {'alert_id': {'$regex': q, '$options': 'i'}},
                        {'normalised_ulf.finding.title': {'$regex': q, '$options': 'i'}},
                        {'normalised_ulf.finding.desc': {'$regex': q, '$options': 'i'}},
                    ]
                },
            ]
        }
    total = await coll.count_documents(match)
    skip = max(0, (page - 1) * limit)
    cursor = coll.find(match).sort([('queued_at', -1)]).skip(skip).limit(limit)
    rows: list[dict[str, Any]] = []
    async for doc in cursor:
        doc.pop('_id', None)
        rows.append(unmapped_dlq_to_list_item(doc))
    return rows, total


async def similar_alerts(db: AsyncIOMotorDatabase, alert_id: str, limit: int = 6) -> list[dict[str, Any]]:
    base = await get_alert_by_id(db, alert_id)
    if not base:
        return []
    bid = base.get('_id')
    if bid is None:
        return []
    src_ip = (base.get('src_endpoint') or {}).get('ip') if isinstance(base.get('src_endpoint'), dict) else None
    cat = base.get('category_uid')
    ors: list[dict[str, Any]] = []
    if src_ip:
        ors.append({'src_endpoint.ip': src_ip})
    if cat is not None:
        ors.append({'category_uid': cat})
    if not ors:
        return []
    match: dict[str, Any] = {'$or': ors, '_id': {'$ne': bid}}
    coll = db[COLLECTION]
    cursor = coll.find(match).sort([('ingestion_timestamp', -1)]).limit(limit)
    out: list[dict[str, Any]] = []
    async for doc in cursor:
        out.append(doc_to_list_item(doc))
    return out


_UNMAPPED_ACTIVE_STATUSES = {'pending_analyst_review', 'pending'}


async def get_unmapped_dlq_doc(db: AsyncIOMotorDatabase, alert_id: str) -> dict[str, Any] | None:
    coll = db[UNMAPPED_COLLECTION]
    q = {'status': {'$in': list(_UNMAPPED_ACTIVE_STATUSES)}}
    doc = await coll.find_one({'alert_id': alert_id, **q})
    if doc is None:
        doc = await coll.find_one(
            {'alert_id': {'$regex': f'^{alert_id}$', '$options': 'i'}, **q}
        )
    return doc


async def promote_unmapped_to_processed(
    db: AsyncIOMotorDatabase,
    alert_id: str,
    *,
    technique_id: str,
    tactic_id: str | None,
    tactic_name: str | None,
    technique_confidence: float,
    analyst_label: str | None,
) -> tuple[bool, str | None]:
    """
    Merge analyst MITRE mapping into `normalised_ulf`, upsert `alerts_processed`, mark DLQ promoted.
    Returns (ok, error_message).
    """
    coll_u = db[UNMAPPED_COLLECTION]
    doc = await get_unmapped_dlq_doc(db, alert_id)
    if not doc:
        return False, 'Unmapped alert not found or already resolved'
    ulf = deepcopy(doc.get('normalised_ulf') or {})
    if not ulf.get('alert_id'):
        ulf['alert_id'] = doc.get('alert_id') or alert_id
    if 'enrichments' not in ulf or not isinstance(ulf['enrichments'], dict):
        ulf['enrichments'] = {}
    mitre = ulf['enrichments'].setdefault('mitre', {})
    if not isinstance(mitre, dict):
        mitre = {}
        ulf['enrichments']['mitre'] = mitre
    mitre['technique_id'] = technique_id.strip()
    if tactic_id:
        mitre['tactic_id'] = tactic_id.strip()
    if tactic_name:
        mitre['tactic_name'] = tactic_name.strip()
    mitre['mapping_method'] = 'analyst_manual'
    mitre['technique_confidence'] = max(0.0, min(1.0, float(technique_confidence)))

    proc = deepcopy(ulf)
    now = datetime.now(UTC)
    proc.setdefault('status', 'open')
    proc['visible_in_fp_review_queue'] = False
    proc['visible_in_soc_queue'] = True
    proc['processing_status'] = 'promoted_from_unmapped'
    proc['processed_at'] = now
    if proc.get('ingestion_timestamp') is None:
        proc['ingestion_timestamp'] = now
    aid = proc.get('alert_id')
    if not aid:
        return False, 'Missing alert_id on ULF'

    if await db[COLLECTION].find_one({'alert_id': aid}):
        return False, 'Alert already exists in alerts_processed'

    await db[COLLECTION].update_one({'alert_id': aid}, {'$set': proc}, upsert=True)

    mapping = {
        'technique_id': technique_id,
        'tactic_id': tactic_id,
        'tactic_name': tactic_name,
        'technique_confidence': technique_confidence,
        'by': analyst_label,
    }
    await coll_u.update_one(
        {'_id': doc['_id']},
        {
            '$set': {
                'status': 'promoted',
                'reviewed_at': now.isoformat(),
                'analyst_mapping': mapping,
            }
        },
    )
    return True, None
