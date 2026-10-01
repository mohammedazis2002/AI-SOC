"""SIEM / source stats for Settings (derived from `alerts_processed`, not a separate connector DB)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.services.alert_source_display import DISPLAY_SOURCE_MONGO_EXPR, SOURCE_KIND_MONGO_EXPR
from app.services.dashboard_stats import COLLECTION

_ACTIVE_WITHIN = timedelta(minutes=30)
_IDLE_WITHIN = timedelta(hours=24)


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


async def build_siem_connections(db: AsyncIOMotorDatabase) -> dict[str, Any]:
    """Per display source: last ingest time, alert count today (UTC), coarse status from recency."""
    now = datetime.now(UTC)
    day_start = datetime(now.year, now.month, now.day, tzinfo=UTC)
    coll = db[COLLECTION]

    base_add = {
        '$addFields': {
            '_display_source': DISPLAY_SOURCE_MONGO_EXPR,
            '_source_kind': SOURCE_KIND_MONGO_EXPR,
            'ts': {'$ifNull': ['$time', '$ingestion_timestamp']},
        }
    }

    overall = await coll.aggregate(
        [
            base_add,
            {'$match': {'ts': {'$ne': None}}},
            {
                '$group': {
                    '_id': '$_display_source',
                    'lastIngest': {'$max': '$ts'},
                    'totalAlerts': {'$sum': 1},
                    'sourceKind': {'$first': '$_source_kind'},
                }
            },
        ]
    ).to_list(None)

    today_rows = await coll.aggregate(
        [
            base_add,
            {'$match': {'ts': {'$gte': day_start, '$lte': now}}},
            {'$group': {'_id': '$_display_source', 'alertsToday': {'$sum': 1}}},
        ]
    ).to_list(None)
    today_map: dict[Any, int] = {r['_id']: int(r['alertsToday']) for r in today_rows}

    connections: list[dict[str, Any]] = []
    for row in overall:
        key = row['_id']
        name = 'Unknown' if key in (None, '', 'Unknown') else str(key)
        last = row.get('lastIngest')
        last_iso: str | None = None
        status = 'inactive'
        if last is not None:
            lu = _utc(last)
            last_iso = lu.isoformat()
            age = now - lu
            if age <= _ACTIVE_WITHIN:
                status = 'active'
            elif age <= _IDLE_WITHIN:
                status = 'idle'
            else:
                status = 'inactive'

        sk = row.get('sourceKind') or 'unknown'
        if sk not in ('siem', 'agent', 'unknown'):
            sk = 'unknown'

        connections.append(
            {
                'name': name,
                'sourceKind': sk,
                'status': status,
                'lastIngestAt': last_iso,
                'alertsToday': today_map.get(key, 0),
                'totalAlerts': int(row.get('totalAlerts', 0)),
            }
        )

    connections.sort(key=lambda x: (-x['totalAlerts'], x['name']))
    return {'connections': connections}
