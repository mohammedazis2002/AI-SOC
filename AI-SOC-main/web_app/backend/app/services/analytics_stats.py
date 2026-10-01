"""Time-series and breakdown analytics from `alerts_processed` (web Analytics page)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.services.dashboard_stats import (
    COLLECTION,
    _RESOLVED_STATUSES,
    _MTTR_MAX_MS,
    _bucket_severity,
    _utc_day_start,
)

def _day_keys(range_start: datetime, now: datetime) -> list[str]:
    keys: list[str] = []
    d0 = range_start
    while d0 <= now:
        keys.append(d0.strftime('%Y-%m-%d'))
        d0 += timedelta(days=1)
    return keys


def _short_label(iso_day: str) -> str:
    try:
        d = datetime.strptime(iso_day, '%Y-%m-%d').replace(tzinfo=UTC)
        return d.strftime('%b %d').replace(' 0', ' ')
    except ValueError:
        return iso_day[-5:]


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


async def build_analytics(db: AsyncIOMotorDatabase, *, days: int) -> dict[str, Any]:
    now = datetime.now(UTC)
    range_start = _utc_day_start(now) - timedelta(days=max(1, days) - 1)
    coll = db[COLLECTION]
    day_keys = _day_keys(range_start, now)

    # --- Volume by severity (ingest day UTC) ---
    vol_pipeline = [
        {'$addFields': {'ts': {'$ifNull': ['$time', '$ingestion_timestamp']}}},
        {'$match': {'ts': {'$gte': range_start, '$lte': now}}},
        {
            '$group': {
                '_id': {
                    'd': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$ts', 'timezone': 'UTC'}},
                    'sev': '$severity_id',
                },
                'c': {'$sum': 1},
            }
        },
    ]
    vol_raw = await coll.aggregate(vol_pipeline).to_list(None)
    vol_map: dict[str, dict[str, int]] = {
        k: {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0} for k in day_keys
    }
    for row in vol_raw:
        day = row['_id']['d']
        if day not in vol_map:
            continue
        vol_map[day][_bucket_severity(row['_id'].get('sev'))] += row['c']

    volume_by_day: list[dict[str, Any]] = []
    for dk in day_keys:
        r = vol_map[dk]
        total = r['critical'] + r['high'] + r['medium'] + r['low'] + r['info']
        volume_by_day.append(
            {
                'date': _short_label(dk),
                'dateIso': dk,
                'critical': r['critical'],
                'high': r['high'],
                'medium': r['medium'],
                'low': r['low'],
                'info': r['info'],
                'total': total,
            }
        )

    totals = [d['total'] for d in volume_by_day]
    period_total = sum(totals)
    peak_day = max(totals) if totals else 0
    avg_per_day = round(period_total / len(totals), 1) if totals else 0

    # --- MTTR by close day (minutes); MTTD TBD ---
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
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$end_ts', 'timezone': 'UTC'}},
                'avg_ms': {'$avg': '$dur_ms'},
                'n': {'$sum': 1},
            }
        },
    ]
    mttr_raw = {row['_id']: ((row['avg_ms'] or 0) / 60000.0) for row in await coll.aggregate(mttr_day_pipeline).to_list(None)}
    mttd_mttr_trend: list[dict[str, Any]] = []
    mttr_vals: list[float] = []
    for dk in day_keys:
        m = round(mttr_raw.get(dk, 0.0), 2)
        if m > 0:
            mttr_vals.append(m)
        mttd_mttr_trend.append({'date': _short_label(dk), 'dateIso': dk, 'mttd': None, 'mttr': m})

    current_mttr_avg = round(sum(mttr_vals) / len(mttr_vals), 1) if mttr_vals else 0

    # --- Auto vs manual closures (by end_ts day) ---
    auto_manual_pipeline: list[dict[str, Any]] = [
        {'$match': {'status': {'$in': list(_RESOLVED_STATUSES)}}},
        _mttr_add_fields(),
        {
            '$match': {
                'end_ts': {'$ne': None},
                'end_ts': {'$gte': range_start, '$lte': now},
            }
        },
        {
            '$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$end_ts', 'timezone': 'UTC'}},
                'auto': {'$sum': {'$cond': [{'$eq': ['$status', 'auto_closed_fp']}, 1, 0]}},
                'manual': {'$sum': {'$cond': [{'$ne': ['$status', 'auto_closed_fp']}, 1, 0]}},
            }
        },
    ]
    am_raw = {row['_id']: row for row in await coll.aggregate(auto_manual_pipeline).to_list(None)}
    auto_vs_manual: list[dict[str, Any]] = []
    auto_sum = manual_sum = 0
    for dk in day_keys:
        row = am_raw.get(dk, {'auto': 0, 'manual': 0})
        a, m = int(row.get('auto', 0)), int(row.get('manual', 0))
        auto_sum += a
        manual_sum += m
        tot = a + m
        if tot > 0:
            auto_vs_manual.append(
                {
                    'date': _short_label(dk),
                    'dateIso': dk,
                    'auto': round(100.0 * a / tot, 1),
                    'manual': round(100.0 * m / tot, 1),
                }
            )
        else:
            auto_vs_manual.append({'date': _short_label(dk), 'dateIso': dk, 'auto': 0, 'manual': 0})
    closure_total = auto_sum + manual_sum
    auto_resolve_pct = round(100.0 * auto_sum / closure_total, 1) if closure_total else 0

    # --- FP rate: false-positive status / alerts ingested that day ---
    fp_statuses = ('false_positive', 'False Positive')
    fp_pipe = [
        {'$addFields': {'ts': {'$ifNull': ['$time', '$ingestion_timestamp']}}},
        {'$match': {'ts': {'$gte': range_start, '$lte': now}}},
        {
            '$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$ts', 'timezone': 'UTC'}},
                'total': {'$sum': 1},
                'fp': {'$sum': {'$cond': [{'$in': ['$status', list(fp_statuses)]}, 1, 0]}},
            }
        },
    ]
    fp_raw = {row['_id']: row for row in await coll.aggregate(fp_pipe).to_list(None)}
    fp_by_day: list[dict[str, Any]] = []
    for dk in day_keys:
        row = fp_raw.get(dk, {'total': 0, 'fp': 0})
        t, fp_n = int(row.get('total', 0)), int(row.get('fp', 0))
        rate = round(100.0 * fp_n / t, 2) if t else 0.0
        fp_by_day.append({'date': _short_label(dk), 'dateIso': dk, 'fpRate': rate})
    recent_fp = fp_by_day[-7:] if len(fp_by_day) >= 7 else fp_by_day
    current_fp_rate = round(sum(d['fpRate'] for d in recent_fp) / len(recent_fp), 2) if recent_fp else 0.0

    # --- Threat intel confidence buckets (0–1 aggregate_score) ---
    conf_pipe = [
        {'$addFields': {'ts': {'$ifNull': ['$time', '$ingestion_timestamp']}}},
        {'$match': {'ts': {'$gte': range_start, '$lte': now}}},
        {'$match': {'enrichments.threat_intel.aggregate_score': {'$exists': True, '$ne': None}}},
        {
            '$group': {
                '_id': None,
                'b0': {
                    '$sum': {
                        '$cond': [
                            {
                                '$and': [
                                    {'$gte': ['$enrichments.threat_intel.aggregate_score', 0]},
                                    {'$lt': ['$enrichments.threat_intel.aggregate_score', 0.2]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                'b1': {
                    '$sum': {
                        '$cond': [
                            {
                                '$and': [
                                    {'$gte': ['$enrichments.threat_intel.aggregate_score', 0.2]},
                                    {'$lt': ['$enrichments.threat_intel.aggregate_score', 0.4]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                'b2': {
                    '$sum': {
                        '$cond': [
                            {
                                '$and': [
                                    {'$gte': ['$enrichments.threat_intel.aggregate_score', 0.4]},
                                    {'$lt': ['$enrichments.threat_intel.aggregate_score', 0.6]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                'b3': {
                    '$sum': {
                        '$cond': [
                            {
                                '$and': [
                                    {'$gte': ['$enrichments.threat_intel.aggregate_score', 0.6]},
                                    {'$lt': ['$enrichments.threat_intel.aggregate_score', 0.8]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                'b4': {
                    '$sum': {
                        '$cond': [
                            {'$gte': ['$enrichments.threat_intel.aggregate_score', 0.8]},
                            1,
                            0,
                        ]
                    }
                },
            }
        },
    ]
    conf_rows = await coll.aggregate(conf_pipe).to_list(1)
    labels = ['0–20%', '20–40%', '40–60%', '60–80%', '80–100%']
    cr = conf_rows[0] if conf_rows else {}
    conf_counts = [int(cr.get('b0', 0)), int(cr.get('b1', 0)), int(cr.get('b2', 0)), int(cr.get('b3', 0)), int(cr.get('b4', 0))]
    confidence_distribution = [{'range': labels[i], 'count': conf_counts[i]} for i in range(5)]

    # --- Top “alert types” (finding title → category → class) ---
    types_pipe: list[dict[str, Any]] = [
        {'$addFields': {'ts': {'$ifNull': ['$time', '$ingestion_timestamp']}}},
        {'$match': {'ts': {'$gte': range_start, '$lte': now}}},
        {
            '$addFields': {
                'atype': {
                    '$ifNull': [
                        '$finding.title',
                        {
                            '$ifNull': [
                                '$category_name',
                                {'$ifNull': ['$class_name', 'Unknown']},
                            ]
                        },
                    ]
                }
            }
        },
        {'$group': {'_id': '$atype', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 10},
    ]
    type_rows = await coll.aggregate(types_pipe).to_list(None)
    top_alert_types = [
        {'name': str(r['_id'])[:120] if r['_id'] else 'Unknown', 'count': r['count']} for r in type_rows
    ]
    type_max = top_alert_types[0]['count'] if top_alert_types else 1

    # --- Top countries (threat intel geolocation) ---
    country_pipe: list[dict[str, Any]] = [
        {'$addFields': {'ts': {'$ifNull': ['$time', '$ingestion_timestamp']}}},
        {'$match': {'ts': {'$gte': range_start, '$lte': now}}},
        {
            '$addFields': {
                'country': {
                    '$ifNull': [
                        '$enrichments.threat_intel.geolocation_summary.country',
                        {
                            '$ifNull': [
                                '$enrichments.threat_intel.geolocation_summary.country_name',
                                None,
                            ]
                        },
                    ]
                }
            }
        },
        {'$match': {'country': {'$nin': [None, '', 'Unknown']}}},
        {'$group': {'_id': '$country', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 10},
    ]
    country_rows = await coll.aggregate(country_pipe).to_list(None)
    top_countries = [{'country': str(r['_id']), 'count': r['count']} for r in country_rows]
    country_max = top_countries[0]['count'] if top_countries else 1

    return {
        'days': days,
        'collection': COLLECTION,
        'volumeByDay': volume_by_day,
        'volumeSummary': {'periodTotal': period_total, 'peakDay': peak_day, 'avgPerDay': avg_per_day},
        'mttdMttrTrend': mttd_mttr_trend,
        'mttdTbd': True,
        'currentMttdAvgMinutes': None,
        'currentMttrAvgMinutes': current_mttr_avg,
        'autoVsManual': auto_vs_manual,
        'autoResolvePct': auto_resolve_pct,
        'fpRateByDay': fp_by_day,
        'currentFpRatePct': current_fp_rate,
        'overrideAvailable': False,
        'overrideRateByDay': [{'date': _short_label(dk), 'dateIso': dk, 'rate': None} for dk in day_keys],
        'confidenceDistribution': confidence_distribution,
        'topAlertTypes': top_alert_types,
        'topAlertTypesMax': type_max,
        'topCountries': top_countries,
        'topCountriesMax': country_max,
    }
