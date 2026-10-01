from __future__ import annotations

import asyncio
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

ALERTS_COLLECTION = 'alerts_processed'
DLQ_COLLECTION = 'normalisation_dlq'
UNMAPPED_COLLECTION = 'unmapped_alerts'
USERS_COLLECTION = 'users'

SERVICE_STATUS_HEALTHY = 'healthy'
SERVICE_STATUS_DEGRADED = 'degraded'
SERVICE_STATUS_DOWN = 'down'


def _unique(values: list[str | None]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value:
            continue
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


def _get_env(name: str, default: str | None = None) -> str | None:
    return os.getenv(name) or os.getenv(name.lower()) or default


def _host_candidates(*values: str | None) -> list[str]:
    return _unique(list(values))


def _format_latency(latency_ms: float | None) -> str | None:
    if latency_ms is None:
        return None
    return f'{int(round(latency_ms))}ms'


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(UTC)
        except ValueError:
            return None
    return None


def _relative_time(value: Any, *, now: datetime) -> str:
    dt = _as_datetime(value)
    if dt is None:
        return 'unknown'
    delta = max((now - dt).total_seconds(), 0)
    if delta < 10:
        return 'just now'
    if delta < 60:
        return f'{int(delta)}s ago'
    if delta < 3600:
        return f'{int(delta // 60)}m ago'
    if delta < 86400:
        return f'{int(delta // 3600)}h ago'
    return f'{int(delta // 86400)}d ago'


def _service_card(
    *,
    service_id: str,
    name: str,
    status: str,
    description: str,
    instances: str | None = None,
    latency_ms: float | None = None,
    last_check: Any = None,
    endpoint: str | None = None,
    details: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        'id': service_id,
        'name': name,
        'status': status,
        'description': description,
        'instances': instances,
        'latency': _format_latency(latency_ms),
        'lastCheck': last_check,
        'endpoint': endpoint,
        'details': details or [],
    }


async def _probe_tcp(hosts: list[str], port: int, *, timeout: float = 1.5) -> dict[str, Any]:
    errors: list[str] = []
    for host in hosts:
        start = time.perf_counter()
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return {
                'ok': True,
                'host': host,
                'port': port,
                'latency_ms': (time.perf_counter() - start) * 1000,
            }
        except Exception as exc:
            errors.append(f'{host}:{port} - {exc}')
    return {'ok': False, 'port': port, 'error': errors[-1] if errors else f'Unable to reach port {port}'}


async def _probe_http(urls: list[str], *, timeout: float = 2.0) -> dict[str, Any]:
    errors: list[str] = []
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        for url in urls:
            start = time.perf_counter()
            try:
                response = await client.get(url)
                latency_ms = (time.perf_counter() - start) * 1000
                if response.status_code < 500:
                    return {
                        'ok': True,
                        'url': url,
                        'latency_ms': latency_ms,
                        'status_code': response.status_code,
                    }
                errors.append(f'{url} - HTTP {response.status_code}')
            except Exception as exc:
                errors.append(f'{url} - {exc}')
    return {'ok': False, 'error': errors[-1] if errors else 'HTTP probe failed'}


async def _probe_mongo(db: AsyncIOMotorDatabase) -> dict[str, Any]:
    start = time.perf_counter()
    try:
        await db.command('ping')
        return {
            'ok': True,
            'latency_ms': (time.perf_counter() - start) * 1000,
        }
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}


async def _load_recent_activity(
    db: AsyncIOMotorDatabase,
    *,
    now: datetime,
) -> dict[str, Any]:
    since = now - timedelta(hours=1)
    cursor = db[ALERTS_COLLECTION].find(
        {
            '$or': [
                {'processed_at': {'$gte': since}},
                {'ingestion_timestamp': {'$gte': since}},
                {'time': {'$gte': since}},
            ]
        },
        {
            'processed_at': 1,
            'ingestion_timestamp': 1,
            'time': 1,
            'severity_id': 1,
        },
    )

    bucket_count = 12
    bucket_size_minutes = 5
    start = (now - timedelta(minutes=(bucket_count - 1) * bucket_size_minutes)).replace(second=0, microsecond=0)
    labels = [(start + timedelta(minutes=i * bucket_size_minutes)).strftime('%H:%M') for i in range(bucket_count)]
    incoming = [0] * bucket_count
    priority = [0] * bucket_count
    processed_last_hour = 0
    last_processed_at: datetime | None = None

    async for doc in cursor:
        ts = _as_datetime(doc.get('processed_at') or doc.get('ingestion_timestamp') or doc.get('time'))
        if ts is None or ts < start:
            continue
        processed_last_hour += 1
        if last_processed_at is None or ts > last_processed_at:
            last_processed_at = ts
        idx = int((ts - start).total_seconds() // (bucket_size_minutes * 60))
        if 0 <= idx < bucket_count:
            incoming[idx] += 1
            try:
                if int(doc.get('severity_id') or 0) >= 4:
                    priority[idx] += 1
            except (TypeError, ValueError):
                continue

    dlq_cursor = db[DLQ_COLLECTION].find(
        {'created_at': {'$gte': start.isoformat()}},
        {'created_at': 1},
    )
    dlq = [0] * bucket_count
    async for doc in dlq_cursor:
        ts = _as_datetime(doc.get('created_at'))
        if ts is None or ts < start:
            continue
        idx = int((ts - start).total_seconds() // (bucket_size_minutes * 60))
        if 0 <= idx < bucket_count:
            dlq[idx] += 1

    return {
        'labels': labels,
        'incoming': incoming,
        'priority': priority,
        'dlq': dlq,
        'processed_last_hour': processed_last_hour,
        # Max timestamp among docs in the chart window only (last ~hour of buckets).
        'last_processed_at': last_processed_at,
    }


async def _latest_alert_activity_globally(db: AsyncIOMotorDatabase) -> datetime | None:
    """Newest processing/ingestion time on any document (any age), for worker liveness."""
    latest: datetime | None = None
    for field in ('processed_at', 'ingestion_timestamp', 'time'):
        doc = await db[ALERTS_COLLECTION].find_one(
            {field: {'$exists': True, '$ne': None}},
            {field: 1},
            sort=[(field, -1)],
        )
        if not doc:
            continue
        ts = _as_datetime(doc.get(field))
        if ts and (latest is None or ts > latest):
            latest = ts
    return latest


async def _load_recent_errors(
    db: AsyncIOMotorDatabase,
    *,
    now: datetime,
) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []

    dlq_rows = await db[DLQ_COLLECTION].find(
        {},
        {
            'reason': 1,
            'validation_errors': 1,
            'created_at': 1,
        },
    ).sort('created_at', -1).limit(4).to_list(4)
    for row in dlq_rows:
        validation_errors = row.get('validation_errors') or []
        detail = validation_errors[0] if validation_errors else row.get('reason') or 'Normalization failure'
        items.append(
            {
                'service': 'Normalization DLQ',
                'error': str(detail)[:180],
                'time': _relative_time(row.get('created_at'), now=now),
            }
        )

    failed_probes = await db[ALERTS_COLLECTION].find(
        {'processing_error': {'$exists': True, '$ne': None}},
        {
            'processing_error': 1,
            'processed_at': 1,
            'ingestion_timestamp': 1,
            'time': 1,
        },
    ).sort([('processed_at', -1), ('ingestion_timestamp', -1), ('time', -1)]).limit(4).to_list(4)
    for row in failed_probes:
        items.append(
            {
                'service': 'Alert Pipeline',
                'error': str(row.get('processing_error'))[:180],
                'time': _relative_time(
                    row.get('processed_at') or row.get('ingestion_timestamp') or row.get('time'),
                    now=now,
                ),
            }
        )

    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        key = (item['service'], item['error'])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[:6]


def _status_from_activity(last_activity: datetime | None, *, now: datetime) -> str:
    """Worker / pipeline status from last seen alert activity (Mongo), not Redis heartbeat."""
    if last_activity is None:
        # Empty DB or no timestamps — idle stack, not a crashed worker.
        return SERVICE_STATUS_HEALTHY
    minutes = (now - last_activity).total_seconds() / 60
    if minutes <= 15:
        return SERVICE_STATUS_HEALTHY
    if minutes <= 60:
        return SERVICE_STATUS_DEGRADED
    return SERVICE_STATUS_DOWN


def _http_candidates(env_var: str | None, default_base: str) -> list[str]:
    explicit = _get_env(env_var) if env_var else None
    bases = _unique([explicit, default_base])
    urls: list[str] = []
    for base in bases:
        parsed = urlparse(base)
        if parsed.scheme and parsed.netloc:
            urls.append(base.rstrip('/') + '/health')
        else:
            urls.append(f'http://{base.rstrip("/")}/health')
    return urls


async def build_system_health(db: AsyncIOMotorDatabase) -> dict[str, Any]:
    now = datetime.now(UTC)

    mongo_task = asyncio.create_task(_probe_mongo(db))
    activity_task = asyncio.create_task(_load_recent_activity(db, now=now))
    global_activity_task = asyncio.create_task(_latest_alert_activity_globally(db))
    errors_task = asyncio.create_task(_load_recent_errors(db, now=now))
    total_alerts_task = asyncio.ensure_future(db[ALERTS_COLLECTION].count_documents({}))
    dlq_count_task = asyncio.ensure_future(db[DLQ_COLLECTION].count_documents({}))
    unmapped_count_task = asyncio.ensure_future(db[UNMAPPED_COLLECTION].count_documents({}))
    pending_users_task = asyncio.ensure_future(db[USERS_COLLECTION].count_documents({'status': 'pending'}))

    redis_task = asyncio.create_task(
        _probe_tcp(_host_candidates(_get_env('REDIS_HOST'), 'redis', 'localhost'), int(_get_env('REDIS_PORT', '6379') or '6379'))
    )
    qdrant_task = asyncio.create_task(
        _probe_tcp(_host_candidates(_get_env('QDRANT_HOST'), 'qdrant', 'localhost'), int(_get_env('QDRANT_PORT', '6333') or '6333'))
    )
    ollama_task = asyncio.create_task(
        _probe_tcp(_host_candidates(_get_env('OLLAMA_HOST'), 'ollama', 'localhost'), int(_get_env('OLLAMA_PORT', '11434') or '11434'))
    )
    vault_host = urlparse(_get_env('VAULT_ADDR', 'http://vault:8200')).hostname or 'vault'
    vault_port = urlparse(_get_env('VAULT_ADDR', 'http://vault:8200')).port or 8200
    vault_task = asyncio.create_task(_probe_tcp(_host_candidates(vault_host, 'localhost'), vault_port))

    agentic_task = asyncio.create_task(_probe_http(_http_candidates('AGENT_API_URL', 'http://agentic-api:8000')))
    asset_risk_task = asyncio.create_task(_probe_http(_http_candidates('ASSET_RISK_URL', 'http://asset-risk-evaluation:5005')))
    anomaly_task = asyncio.create_task(_probe_http(_http_candidates('ANOMALY_DETECTION_URL', 'http://anomaly-detection:5001')))
    attack_stage_task = asyncio.create_task(_probe_http(_http_candidates('ATTACK_STAGE_URL', 'http://attack-stage-predictor:5002')))
    forecast_task = asyncio.create_task(_probe_http(_http_candidates('ATTACK_FORECASTING_URL', 'http://attack-forecasting:5003')))
    fp_task = asyncio.create_task(_probe_http(_http_candidates('FALSE_POSITIVE_URL', 'http://false-positive-detector:5004')))
    root_cause_task = asyncio.create_task(_probe_http(_http_candidates('ROOT_CAUSE_URL', 'http://root-cause-analyzer:5006')))

    (
        mongo,
        activity,
        global_last_activity,
        recent_errors,
        total_alerts,
        dlq_count,
        unmapped_count,
        pending_users,
        redis,
        qdrant,
        ollama,
        vault,
        agentic,
        asset_risk,
        anomaly,
        attack_stage,
        forecast,
        fp_detector,
        root_cause,
    ) = await asyncio.gather(
        mongo_task,
        activity_task,
        global_activity_task,
        errors_task,
        total_alerts_task,
        dlq_count_task,
        unmapped_count_task,
        pending_users_task,
        redis_task,
        qdrant_task,
        ollama_task,
        vault_task,
        agentic_task,
        asset_risk_task,
        anomaly_task,
        attack_stage_task,
        forecast_task,
        fp_task,
        root_cause_task,
    )

    dlq_backlog = int(dlq_count or 0) + int(unmapped_count or 0)
    worker_status = _status_from_activity(global_last_activity, now=now)

    services = [
        _service_card(
            service_id='web-app-api',
            name='Web App API',
            status=SERVICE_STATUS_HEALTHY,
            description='Auth, admin, dashboard, and system analytics API.',
            instances='1/1',
            latency_ms=0,
            last_check='just now',
            endpoint='/system/health',
            details=[
                {'label': 'Surface', 'value': 'frontend auth API'},
                {'label': 'Pending approvals', 'value': str(pending_users)},
            ],
        ),
        _service_card(
            service_id='mongodb',
            name='MongoDB',
            status=SERVICE_STATUS_HEALTHY if mongo.get('ok') else SERVICE_STATUS_DOWN,
            description='Primary data store for alerts, users, queues, and audit history.',
            instances='1/1',
            latency_ms=mongo.get('latency_ms'),
            last_check='just now',
            endpoint=f'{_get_env("MONGODB_HOST", "mongodb")}:{_get_env("MONGODB_PORT", "27017")}',
            details=[
                {'label': 'Alerts stored', 'value': str(total_alerts)},
                {'label': 'DLQ backlog', 'value': str(dlq_backlog)},
            ],
        ),
        _service_card(
            service_id='alert-worker',
            name='Alert Processor Worker',
            status=worker_status,
            description='Inferred from latest timestamps on alerts_processed (Mongo), not Redis consumer lag.',
            instances='event-driven',
            last_check=_relative_time(global_last_activity, now=now) if global_last_activity else 'no alerts in database',
            details=[
                {'label': 'Processed in last hour', 'value': str(activity.get('processed_last_hour', 0))},
                {
                    'label': 'Latest alert activity',
                    'value': _relative_time(global_last_activity, now=now) if global_last_activity else 'none',
                },
            ],
        ),
        _service_card(
            service_id='redis',
            name='Redis Streams',
            status=SERVICE_STATUS_HEALTHY if redis.get('ok') else SERVICE_STATUS_DOWN,
            description='Queue backbone for alert ingestion, priorities, and transient cache.',
            instances='1/1',
            latency_ms=redis.get('latency_ms'),
            last_check='just now',
            endpoint=f'{redis.get("host", _get_env("REDIS_HOST", "redis"))}:{redis.get("port", _get_env("REDIS_PORT", "6379"))}',
            details=[
                {'label': 'Incoming bucket peak', 'value': str(max(activity.get('incoming', [0]) or [0]))},
                {'label': 'Priority bucket peak', 'value': str(max(activity.get('priority', [0]) or [0]))},
            ],
        ),
        _service_card(
            service_id='qdrant',
            name='Qdrant',
            status=SERVICE_STATUS_HEALTHY if qdrant.get('ok') else SERVICE_STATUS_DOWN,
            description='Vector database supporting retrieval and knowledge lookups.',
            instances='1/1',
            latency_ms=qdrant.get('latency_ms'),
            last_check='just now',
            endpoint=f'{qdrant.get("host", _get_env("QDRANT_HOST", "qdrant"))}:{qdrant.get("port", _get_env("QDRANT_PORT", "6333"))}',
        ),
        _service_card(
            service_id='vault',
            name='Vault',
            status=SERVICE_STATUS_HEALTHY if vault.get('ok') else SERVICE_STATUS_DOWN,
            description='Certificate authority and secrets plane used by the mTLS stack.',
            instances='1/1',
            latency_ms=vault.get('latency_ms'),
            last_check='just now',
            endpoint=f'{vault.get("host", vault_host)}:{vault.get("port", vault_port)}',
        ),
        _service_card(
            service_id='agentic-api',
            name='Agentic API',
            status=SERVICE_STATUS_HEALTHY if agentic.get('ok') else SERVICE_STATUS_DOWN,
            description='Autonomous response and orchestration API.',
            instances='1/1',
            latency_ms=agentic.get('latency_ms'),
            last_check='just now',
            endpoint=agentic.get('url'),
        ),
        _service_card(
            service_id='asset-risk',
            name='Asset Risk Evaluation',
            status=SERVICE_STATUS_HEALTHY if asset_risk.get('ok') else SERVICE_STATUS_DOWN,
            description='Asset profiling and risk scoring microservice.',
            instances='1/1',
            latency_ms=asset_risk.get('latency_ms'),
            last_check='just now',
            endpoint=asset_risk.get('url'),
        ),
        _service_card(
            service_id='anomaly',
            name='Anomaly Detection',
            status=SERVICE_STATUS_HEALTHY if anomaly.get('ok') else SERVICE_STATUS_DOWN,
            description='Behavioral anomaly scoring for processed alerts.',
            instances='1/1',
            latency_ms=anomaly.get('latency_ms'),
            last_check='just now',
            endpoint=anomaly.get('url'),
        ),
        _service_card(
            service_id='attack-stage',
            name='Attack Stage Predictor',
            status=SERVICE_STATUS_HEALTHY if attack_stage.get('ok') else SERVICE_STATUS_DOWN,
            description='MITRE stage enrichment and progression prediction.',
            instances='1/1',
            latency_ms=attack_stage.get('latency_ms'),
            last_check='just now',
            endpoint=attack_stage.get('url'),
        ),
        _service_card(
            service_id='attack-forecast',
            name='Attack Forecasting',
            status=SERVICE_STATUS_HEALTHY if forecast.get('ok') else SERVICE_STATUS_DOWN,
            description='Predictive service for likely follow-on attack behavior.',
            instances='1/1',
            latency_ms=forecast.get('latency_ms'),
            last_check='just now',
            endpoint=forecast.get('url'),
        ),
        _service_card(
            service_id='fp-detector',
            name='False Positive Detector',
            status=SERVICE_STATUS_HEALTHY if fp_detector.get('ok') else SERVICE_STATUS_DOWN,
            description='Classifier that suppresses noisy detections before analyst review.',
            instances='1/1',
            latency_ms=fp_detector.get('latency_ms'),
            last_check='just now',
            endpoint=fp_detector.get('url'),
        ),
        _service_card(
            service_id='root-cause',
            name='Root Cause Analyzer',
            status=SERVICE_STATUS_HEALTHY if root_cause.get('ok') else SERVICE_STATUS_DOWN,
            description='LLM-assisted root cause analysis and case enrichment.',
            instances='1/1',
            latency_ms=root_cause.get('latency_ms'),
            last_check='just now',
            endpoint=root_cause.get('url'),
        ),
        _service_card(
            service_id='ollama',
            name='Ollama',
            status=SERVICE_STATUS_HEALTHY if ollama.get('ok') else SERVICE_STATUS_DOWN,
            description='Local inference runtime backing model-powered workflows.',
            instances='1/1',
            latency_ms=ollama.get('latency_ms'),
            last_check='just now',
            endpoint=f'{ollama.get("host", _get_env("OLLAMA_HOST", "ollama"))}:{ollama.get("port", _get_env("OLLAMA_PORT", "11434"))}',
        ),
    ]

    for service, probe in (
        ('MongoDB', mongo),
        ('Redis Streams', redis),
        ('Qdrant', qdrant),
        ('Vault', vault),
        ('Agentic API', agentic),
        ('Asset Risk Evaluation', asset_risk),
        ('Anomaly Detection', anomaly),
        ('Attack Stage Predictor', attack_stage),
        ('Attack Forecasting', forecast),
        ('False Positive Detector', fp_detector),
        ('Root Cause Analyzer', root_cause),
        ('Ollama', ollama),
    ):
        if not probe.get('ok'):
            recent_errors.append(
                {
                    'service': service,
                    'error': str(probe.get('error') or 'Health probe failed')[:180],
                    'time': 'just now',
                }
            )

    healthy_services = sum(1 for service in services if service['status'] == SERVICE_STATUS_HEALTHY)
    degraded_services = sum(1 for service in services if service['status'] == SERVICE_STATUS_DEGRADED)
    down_services = sum(1 for service in services if service['status'] == SERVICE_STATUS_DOWN)

    return {
        'generatedAt': now.isoformat(),
        'summary': {
            'totalServices': len(services),
            'healthyServices': healthy_services,
            'degradedServices': degraded_services,
            'downServices': down_services,
            'alertsStored': total_alerts,
            'processedLastHour': activity.get('processed_last_hour', 0),
            'dlqBacklog': dlq_backlog,
            'pendingApprovals': pending_users,
        },
        'services': services,
        'queueDepth': {
            'labels': activity.get('labels', []),
            'incoming': activity.get('incoming', []),
            'priority': activity.get('priority', []),
            'dlq': activity.get('dlq', []),
        },
        'recentErrors': recent_errors[:8],
    }
