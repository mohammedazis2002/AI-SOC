"""Aggregated metrics from `alerts_processed` for the SOC dashboard."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.services.alert_source_display import DISPLAY_SOURCE_MONGO_EXPR

COLLECTION = 'alerts_processed'

# Resolved / closed-style statuses (same family as auto-resolved counts)
_RESOLVED_STATUSES: tuple[str, ...] = (
    'resolved',
    'Resolved',
    'false_positive',
    'False Positive',
    'closed',
    'Closed',
    'auto_closed_fp',
)

# Cap MTTR duration at 30 days to exclude bad timestamps
_MTTR_MAX_MS = 30 * 86400 * 1000

# OCSF severity_id (ulf_schema.SeverityEnum)
_SEV_CRITICAL = 5
_SEV_HIGH = 4
_SEV_MEDIUM = 3
_SEV_LOW = 2
_SEV_INFORMATIONAL = 1
_SEV_UNKNOWN = 0


def _utc_day_start(dt: datetime) -> datetime:
    d = dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    return datetime(d.year, d.month, d.day, tzinfo=UTC)


def _bucket_severity(severity_id: Any) -> str:
    try:
        sid = int(severity_id)
    except (TypeError, ValueError):
        return 'info'
    if sid == _SEV_CRITICAL:
        return 'critical'
    if sid == _SEV_HIGH:
        return 'high'
    if sid == _SEV_MEDIUM:
        return 'medium'
    if sid == _SEV_LOW:
        return 'low'
    return 'info'


def _severity_to_badge(severity_id: Any, severity_label: Any) -> str:
    """Frontend SeverityBadge expects CRITICAL | HIGH | MEDIUM | LOW | INFO."""
    if isinstance(severity_label, str) and severity_label.strip():
        u = severity_label.strip().upper()
        if u in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'INFORMATIONAL', 'UNKNOWN'):
            if u == 'INFORMATIONAL':
                return 'INFO'
            if u == 'UNKNOWN':
                return 'INFO'
            return u
    b = _bucket_severity(severity_id)
    return {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW', 'info': 'INFO'}[b]


async def build_dashboard_summary(db: AsyncIOMotorDatabase, *, days: int = 14) -> dict[str, Any]:
    now = datetime.now(UTC)
    day_start = _utc_day_start(now)
    yesterday_start = day_start - timedelta(days=1)
    range_start = day_start - timedelta(days=max(1, days) - 1)
    coll = db[COLLECTION]

    total_alerts = await coll.count_documents({})

    count_today = await coll.count_documents(
        {
            '$or': [
                {'time': {'$gte': day_start}},
                {'ingestion_timestamp': {'$gte': day_start}},
            ]
        }
    )
    count_yesterday = await coll.count_documents(
        {
            '$or': [
                {'time': {'$gte': yesterday_start, '$lt': day_start}},
                {'ingestion_timestamp': {'$gte': yesterday_start, '$lt': day_start}},
            ]
        }
    )
    denom = max(count_yesterday, 1)
    total_delta = (count_today - count_yesterday) / denom

    critical_count = await coll.count_documents({'severity_id': _SEV_CRITICAL})
    high_count = await coll.count_documents({'severity_id': _SEV_HIGH})
    critical_high = critical_count + high_count

    prior_start = range_start - timedelta(days=max(1, days))
    pipeline_ch_prev = [
        {
            '$match': {
                '$or': [
                    {'time': {'$gte': prior_start, '$lt': range_start}},
                    {'ingestion_timestamp': {'$gte': prior_start, '$lt': range_start}},
                ]
            }
        },
        {'$match': {'severity_id': {'$in': [_SEV_CRITICAL, _SEV_HIGH]}}},
        {'$count': 'c'},
    ]
    prev_ch = await coll.aggregate(pipeline_ch_prev).to_list(1)
    prev_critical_high = prev_ch[0]['c'] if prev_ch else 0
    cur_ch_pipeline = [
        {
            '$match': {
                '$or': [
                    {'time': {'$gte': range_start}},
                    {'ingestion_timestamp': {'$gte': range_start}},
                ]
            }
        },
        {'$match': {'severity_id': {'$in': [_SEV_CRITICAL, _SEV_HIGH]}}},
        {'$count': 'c'},
    ]
    cur_ch_list = await coll.aggregate(cur_ch_pipeline).to_list(1)
    current_critical_high = cur_ch_list[0]['c'] if cur_ch_list else 0
    critical_high_delta = current_critical_high - prev_critical_high

    # Resolved / false positive style statuses
    resolved_like = await coll.count_documents({'status': {'$in': list(_RESOLVED_STATUSES)}})
    auto_resolved_pct = round(100.0 * resolved_like / total_alerts) if total_alerts else 0

    pending_review = await coll.count_documents(
        {
            'status': {
                '$in': [
                    'open',
                    'Open',
                    'new',
                    'New',
                    'in_review',
                    'in progress',
                    'In Progress',
                ]
            }
        }
    )

    # Volume by calendar day + severity (last `days` days)
    vol_pipeline = [
        {
            '$addFields': {
                'ts': {'$ifNull': ['$time', '$ingestion_timestamp']},
            }
        },
        {'$match': {'ts': {'$gte': range_start, '$lte': now}}},
        {
            '$group': {
                '_id': {
                    'd': {
                        '$dateToString': {'format': '%Y-%m-%d', 'date': '$ts', 'timezone': 'UTC'},
                    },
                    'sev': '$severity_id',
                },
                'c': {'$sum': 1},
            }
        },
    ]
    vol_raw = await coll.aggregate(vol_pipeline).to_list(None)

    day_keys: list[str] = []
    d0 = range_start
    while d0 <= now:
        day_keys.append(d0.strftime('%Y-%m-%d'))
        d0 += timedelta(days=1)

    vol_map: dict[str, dict[str, int]] = {k: {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0} for k in day_keys}
    for row in vol_raw:
        day = row['_id']['d']
        if day not in vol_map:
            continue
        bucket = _bucket_severity(row['_id'].get('sev'))
        vol_map[day][bucket] += row['c']

    alert_volume_by_day = [
        {
            'date': dk[5:] if len(dk) >= 10 else dk,
            'critical': vol_map[dk]['critical'],
            'high': vol_map[dk]['high'],
            'medium': vol_map[dk]['medium'],
            'low': vol_map[dk]['low'],
            'info': vol_map[dk]['info'],
        }
        for dk in day_keys
    ]

    # SIEM / agent grouping (shared expr in `alert_source_display`)
    src_pipeline = [
        {'$addFields': {'_display_source': DISPLAY_SOURCE_MONGO_EXPR}},
        {'$group': {'_id': '$_display_source', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
    ]
    src_rows = await coll.aggregate(src_pipeline).to_list(None)
    alerts_by_source = [
        {
            'name': 'Unknown' if row['_id'] in (None, '', 'Unknown') else str(row['_id']),
            'value': row['count'],
            'count': row['count'],
        }
        for row in src_rows
    ]

    # Recent alerts for list widget
    cursor = coll.find(
        {},
        {
            'alert_id': 1,
            'finding': 1,
            'severity': 1,
            'severity_id': 1,
            'status': 1,
            'time': 1,
            'ingestion_timestamp': 1,
        },
    ).sort([('ingestion_timestamp', -1), ('time', -1)]).limit(12)
    recent: list[dict[str, Any]] = []
    async for doc in cursor:
        ts = doc.get('time') or doc.get('ingestion_timestamp')
        ts_iso = ts.isoformat() if hasattr(ts, 'isoformat') else datetime.now(UTC).isoformat()
        finding = doc.get('finding') or {}
        desc = finding.get('title') or finding.get('desc') or doc.get('alert_id') or 'Alert'
        recent.append(
            {
                'id': doc.get('alert_id') or str(doc.get('_id')),
                'description': str(desc)[:200],
                'severity': _severity_to_badge(doc.get('severity_id'), doc.get('severity')),
                'status': _normalize_status_for_ui(doc.get('status')),
                'timestamp': ts_iso,
            }
        )

    # MTTD: SOC-wide definition still TBD — do not surface a misleading average
    mttd_tbd = True

    # MTTR: mean(end - start) in minutes for resolved-like alerts closed in [range_start, now].
    # end_ts := resolved_at | closed_at | updated_at | processed_at (fallback)
    # start_ts := time | ingestion_timestamp
    def _mttr_add_fields() -> dict[str, Any]:
        return {
            '$addFields': {
                'start_ts': {'$ifNull': ['$time', '$ingestion_timestamp']},
                'end_ts': {
                    '$ifNull': [
                        '$resolved_at',
                        {
                            '$ifNull': [
                                '$closed_at',
                                {'$ifNull': ['$updated_at', '$processed_at']},
                            ]
                        },
                    ]
                },
            }
        }

    async def _mttr_avg_between(
        t0: datetime,
        t1: datetime,
        *,
        t0_inclusive: bool = True,
        t1_inclusive: bool = True,
    ) -> tuple[float, int]:
        end_match: dict[str, Any] = {}
        if t0_inclusive:
            end_match['$gte'] = t0
        else:
            end_match['$gt'] = t0
        if t1_inclusive:
            end_match['$lte'] = t1
        else:
            end_match['$lt'] = t1
        pipe: list[dict[str, Any]] = [
            {'$match': {'status': {'$in': list(_RESOLVED_STATUSES)}}},
            _mttr_add_fields(),
            {
                '$match': {
                    'start_ts': {'$ne': None},
                    'end_ts': {'$ne': None},
                    'end_ts': end_match,
                }
            },
            {'$addFields': {'dur_ms': {'$subtract': ['$end_ts', '$start_ts']}}},
            {'$match': {'dur_ms': {'$gte': 0, '$lte': _MTTR_MAX_MS}}},
            {'$group': {'_id': None, 'avg_ms': {'$avg': '$dur_ms'}, 'n': {'$sum': 1}}},
        ]
        rows = await coll.aggregate(pipe).to_list(1)
        if not rows or not rows[0].get('n'):
            return 0.0, 0
        avg_ms = float(rows[0].get('avg_ms') or 0)
        return avg_ms / 60000.0, int(rows[0]['n'])

    mttr_avg_minutes, mttr_n = await _mttr_avg_between(range_start, now)

    span = now - range_start
    mid = range_start + span / 2 if span.total_seconds() > 3600 else range_start
    prior_avg, prior_n = await _mttr_avg_between(range_start, mid, t1_inclusive=False) if mid > range_start else (0.0, 0)
    recent_avg, recent_n = await _mttr_avg_between(mid, now, t0_inclusive=True)
    mttr_delta = 0.0
    if prior_n > 0 and recent_n > 0 and prior_avg > 0:
        mttr_delta = (recent_avg - prior_avg) / prior_avg
    elif prior_n > 0 and recent_n > 0 and prior_avg == 0 and recent_avg > 0:
        mttr_delta = 1.0

    # Per-day average MTTR (minutes) for sparkline — alerts whose end_ts falls on that UTC day
    mttr_day_pipeline: list[dict[str, Any]] = [
        {'$match': {'status': {'$in': list(_RESOLVED_STATUSES)}}},
        _mttr_add_fields(),
        {
            '$match': {
                'start_ts': {'$ne': None},
                'end_ts': {'$ne': None},
                'end_ts': {'$gte': range_start, '$lte': now},
            }
        },
        {'$addFields': {'dur_ms': {'$subtract': ['$end_ts', '$start_ts']}}},
        {'$match': {'dur_ms': {'$gte': 0, '$lte': _MTTR_MAX_MS}}},
        {
            '$group': {
                '_id': {
                    '$dateToString': {'format': '%Y-%m-%d', 'date': '$end_ts', 'timezone': 'UTC'},
                },
                'avg_ms': {'$avg': '$dur_ms'},
                'n': {'$sum': 1},
            }
        },
    ]
    mttr_by_day_raw = await coll.aggregate(mttr_day_pipeline).to_list(None)
    mttr_day_map = {row['_id']: (row['avg_ms'] or 0) / 60000.0 for row in mttr_by_day_raw}
    mttr_sparkline = [round(mttr_day_map.get(dk, 0.0), 1) for dk in day_keys]

    return {
        'totalAlerts': total_alerts,
        'totalDelta': round(total_delta, 4),
        'criticalCount': critical_count,
        'highCount': high_count,
        'criticalHigh': critical_high,
        'criticalHighDelta': critical_high_delta,
        'autoResolved': resolved_like,
        'autoResolvedPct': auto_resolved_pct,
        'autoResolvedDelta': 0.0,
        'pendingReview': pending_review,
        'slaAtRisk': pending_review > 5,
        'mttdTbd': mttd_tbd,
        'mttdAvgMinutes': None,
        'mttdDelta': None,
        'mttdSparkline': [],
        'mttrAvgMinutes': int(round(mttr_avg_minutes)) if mttr_n else 0,
        'mttrSampleCount': mttr_n,
        'mttrDelta': round(mttr_delta, 4),
        'mttrSparkline': mttr_sparkline,
        'alertVolumeByDay': alert_volume_by_day,
        'alertsBySource': alerts_by_source,
        'recentAutomatedActions': [],
        'recentAlerts': recent,
    }


def _normalize_status_for_ui(status: Any) -> str:
    if not status:
        return 'new'
    s = str(status).lower().replace(' ', '_')
    mapping = {
        'open': 'new',
        'new': 'new',
        'in_progress': 'in_review',
        'in review': 'in_review',
        'resolved': 'resolved',
        'false_positive': 'false_positive',
        'escalated': 'escalated',
    }
    return mapping.get(s, 'new')
