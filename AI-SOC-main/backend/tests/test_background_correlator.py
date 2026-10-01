"""
Test Background Correlator (Path C)
=====================================
Covers CircuitBreaker, engine setup, workers, 6 correlation layers,
fallback mechanisms, incident tracking integration and dead letter queue.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from services.correlation.background_correlator import (
    BackgroundCorrelationEngine,
    _CircuitBreaker,
    _LAYER_TIMEOUTS,
    QUEUE_MAX_SIZE,
    _CB_FAILURE_THRESHOLD,
    _CB_RECOVERY_TIMEOUT_S,
    CONFIDENCE_THRESHOLD,
    BACKGROUND_WORKERS
)
from services.correlation.models import AlertRef, CorrelationResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    db = MagicMock()
    db.alerts.find.return_value.limit.return_value = []
    # Support iteration directly on the mock returned by find(...)
    # By default, mock returns MagicMock when called, let's configure `find().limit()`
    return db

@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    return redis

@pytest.fixture
def mock_incident_tracker():
    tracker = AsyncMock()
    tracker.find_incident_by_alerts.return_value = None
    return tracker

@pytest.fixture
def engine(mock_db, mock_redis, mock_incident_tracker):
    return BackgroundCorrelationEngine(
        incident_tracker=mock_incident_tracker,
        db_client=mock_db,
        redis_client=mock_redis
    )

# ---------------------------------------------------------------------------
# _CircuitBreaker Tests
# ---------------------------------------------------------------------------

def test_circuit_breaker():
    cb = _CircuitBreaker("test")
    assert not cb.is_open

    cb.record_success()
    assert not cb.is_open

    # trigger failures
    for _ in range(_CB_FAILURE_THRESHOLD):
        cb.record_failure()
    assert cb.is_open

    # wait out the recovery timeout
    with patch("time.monotonic", return_value=time.monotonic() + _CB_RECOVERY_TIMEOUT_S + 1):
        # Half-open, should allow attempt
        assert not cb.is_open
        # Now if we record a success, it should fully recover
        cb.record_success()
        assert not cb.is_open


# ---------------------------------------------------------------------------
# Engine start & enqueue
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_engine_start_enqueue(engine):
    engine.start()
    assert engine._workers_started
    # Call again, should be completely safe/no-op
    engine.start()

    alert = {"alert_id": "a1"}
    success = await engine.enqueue(alert)
    assert success is True
    assert engine.queue_depth == 1
    assert engine.overflow_count == 0

    # Cancel background tasks so they don't leak
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for t in tasks:
        t.cancel()

    # Wait for cancellation
    await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_engine_queue_overflow(engine):
    # Mock the internal queue to raise QueueFull
    with patch.object(engine._queue, "put_nowait", side_effect=asyncio.QueueFull):
        success = await engine.enqueue({"alert_id": "a1"})
        assert success is False
        assert engine.overflow_count == 1
        assert engine.queue_depth == 0


# ---------------------------------------------------------------------------
# Worker tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_worker_processing_success(engine):
    alert = {"alert_id": "a1"}
    await engine.enqueue(alert)

    # Patch deep_correlate to return a valid result
    with patch.object(engine, "deep_correlate", new_callable=AsyncMock) as mock_deep:
        mock_deep.return_value = {
            "correlated": True,
            "confidence": 0.9,
            "related_alerts": ["a2", "a3"],
            "attack_pattern": "phishing",
            "ml_degraded": False,
            "narrative": "Test narrative"
        }
        
        with patch.object(engine, "_handle_correlation_found", new_callable=AsyncMock) as mock_handle:
            # Manually run the worker loop once
            worker_task = asyncio.create_task(engine._worker(1))
            try:
                await asyncio.sleep(0.05) # let it process
                mock_deep.assert_called_once_with(alert)
                mock_handle.assert_called_once()
            finally:
                worker_task.cancel()
                try:
                    await worker_task
                except asyncio.CancelledError:
                    pass

@pytest.mark.asyncio
async def test_worker_processing_failure_dlq(engine):
    alert = {"alert_id": "a1"}
    await engine.enqueue(alert)

    # Patch deep_correlate to raise exception
    with patch.object(engine, "deep_correlate", new_callable=AsyncMock) as mock_deep:
        mock_deep.side_effect = ValueError("Deep corr failed")
        
        worker_task = asyncio.create_task(engine._worker(1))
        try:
            # yielding to event loop is more reliable
            await asyncio.sleep(0.05)
            
            engine._redis.xadd.assert_called_once()
            args, kwargs = engine._redis.xadd.call_args
            assert args[0] == "corr:dlq"
        finally:
            worker_task.cancel()
            try:
                await worker_task
            except asyncio.CancelledError:
                pass

@pytest.mark.asyncio
async def test_dlq_no_redis(engine):
    engine._redis = None
    # Just ensure it doesn't crash
    await engine._send_to_dlq({"alert_id": "a1"}, "error")


# ---------------------------------------------------------------------------
# Helper _timed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_timed_wrapper(engine):
    async def slow_func():
        await asyncio.sleep(0.1)
        return 1.0, ["a1"]

    # success case
    with patch.dict(_LAYER_TIMEOUTS, {"temporal": 1}):
        res = await engine._timed("temporal", slow_func())
        assert res == (1.0, ["a1"])

    # timeout case
    with patch.dict(_LAYER_TIMEOUTS, {"temporal": 0.01}):
        res = await engine._timed("temporal", slow_func())
        assert res == (0.0, [])

    with patch.dict(_LAYER_TIMEOUTS, {"pattern": 0.01}):
        res = await engine._timed("pattern", slow_func())
        assert res == (0.0, [], None)
        
    with patch.dict(_LAYER_TIMEOUTS, {"ml": 0.01}):
        res = await engine._timed("ml", slow_func())
        assert res == (0.0, True)

    async def fail_func():
        raise ValueError("failed layer")

    res = await engine._timed("temporal", fail_func())
    assert res == (0.0, [])


# ---------------------------------------------------------------------------
# ML Layer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_layer_ml_success(engine):
    alert = {"alert_id": "a1"}
    
    mock_resp_anomaly = MagicMock()
    mock_resp_anomaly.json.return_value = {"anomaly_score": 0.8}
    mock_resp_anomaly.raise_for_status = MagicMock()

    mock_resp_attack = MagicMock()
    mock_resp_attack.json.return_value = {"attack_stage": "exploitation"}  # score = 0.85
    mock_resp_attack.raise_for_status = MagicMock()

    with patch.object(engine._http, "post", new_callable=AsyncMock) as mock_post:
        # Provide responses depending on URL
        def side_effect(*args, **kwargs):
            if "anomaly-detection" in args[0]:
                return mock_resp_anomaly
            elif "attack-stage" in args[0]:
                return mock_resp_attack
            return mock_resp_anomaly
        mock_post.side_effect = side_effect

        score, degraded = await engine._layer_ml(alert)
        assert score == 0.825  # (0.8 + 0.85) / 2
        assert not degraded

@pytest.mark.asyncio
async def test_layer_ml_failure(engine):
    alert = {"alert_id": "a1"}
    
    with patch.object(engine._http, "post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.RequestError("network error")

        score, degraded = await engine._layer_ml(alert)
        assert score == 0.0
        assert degraded is True
        assert engine._cb_anomaly._failures > 0
        assert engine._cb_attack_stage._failures > 0

@pytest.mark.asyncio
async def test_layer_ml_cb_open(engine):
    alert = {"alert_id": "a1"}
    
    engine._cb_anomaly._open_since = time.monotonic()
    engine._cb_attack_stage._open_since = time.monotonic()
    
    with patch.object(engine._http, "post", new_callable=AsyncMock) as mock_post:
        score, degraded = await engine._layer_ml(alert)
        assert mock_post.call_count == 0
        assert score == 0.0
        assert degraded is True


# ---------------------------------------------------------------------------
# Other Layers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_layer_temporal(engine):
    ref = AlertRef.from_alert({"alert_id": "a1", "user": "test_user"})
    
    # Missing DB
    engine._db = None
    assert await engine._layer_temporal(ref) == (0.0, [])
    
    engine._db = MagicMock()
    engine._db.alerts.find.return_value.limit.return_value = [{"alert_id": "a2"}, {"alert_id": "a3"}]
    
    score, alerts = await engine._layer_temporal(ref)
    assert score == 2.0 / 5.0
    assert alerts == ["a2", "a3"]

@pytest.mark.asyncio
async def test_layer_entity(engine):
    ref = AlertRef.from_alert({"alert_id": "a1", "source_ip": "10.0.0.1"})
    engine._db.alerts.find.return_value.limit.return_value = [{"alert_id": "a2"}] * 10
    
    score, matches = await engine._layer_entity(ref)
    assert score == 1.0
    assert len(matches) == 10

@pytest.mark.asyncio
async def test_layer_pattern(engine):
    # Match T1056.001 with precursor T1566
    ref = AlertRef.from_alert({"alert_id": "a1", "user": "test_user", "mitre_technique": "T1056.001"})
    engine._db.alerts.find.return_value.limit.return_value = [{"alert_id": "a2"}]
    
    score, alerts, name = await engine._layer_pattern(ref)
    assert score == 0.9
    assert alerts == ["a2"]
    assert name == "phishing_credential_theft"
    
    # Missing technique
    ref_no_tech = AlertRef.from_alert({"alert_id": "a1", "user": "test", "mitre_technique": ""})
    score, alerts, name = await engine._layer_pattern(ref_no_tech)
    assert score == 0.0

@pytest.mark.asyncio
async def test_layer_graph(engine):
    ref = AlertRef.from_alert({"alert_id": "a1", "user": "test_user"})
    
    # 2 hop graph
    hop1_docs = [{"alert_id": "a2", "user": "u2", "source_ip": "ip1"}, {"alert_id": "a3"}]
    hop2_docs = [{"alert_id": "a4"}]
    
    mock_db = MagicMock()
    mock_db.alerts.find.return_value.limit.side_effect = [hop1_docs, hop2_docs]
    engine._db = mock_db
    
    score, alerts = await engine._layer_graph(ref)
    assert "a2" in alerts
    assert "a3" in alerts
    assert "a4" in alerts
    assert score == 3.0 / 15.0

@pytest.mark.asyncio
async def test_layer_behavioral(engine):
    ref = AlertRef.from_alert({"alert_id": "a1", "user": "test_user", "severity": "critical"}) # 4
    
    past_alerts = [
        {"alert_id": "a2", "severity": "low"}, # 1
        {"alert_id": "a3", "severity": "low"}, # 1
    ]
    engine._db.alerts.find.return_value.limit.return_value = past_alerts
    
    score, alerts = await engine._layer_behavioral(ref)
    # avg = 1, current = 4, dev = (4-1)/3 = 1.0
    assert score == 1.0
    assert alerts == ["a2", "a3"]

@pytest.mark.asyncio
async def test_deep_correlate(engine):
    alert = {"alert_id": "a1", "user": "test", "mitre_technique": "T1056.001", "severity": "critical"}
    
    with patch.object(engine, "_layer_temporal", new_callable=AsyncMock, return_value=(1.0, ["a2"])), \
         patch.object(engine, "_layer_entity", new_callable=AsyncMock, return_value=(1.0, ["a3"])), \
         patch.object(engine, "_layer_pattern", new_callable=AsyncMock, return_value=(0.9, ["a4"], "phish")), \
         patch.object(engine, "_layer_graph", new_callable=AsyncMock, return_value=(1.0, ["a5"])), \
         patch.object(engine, "_layer_behavioral", new_callable=AsyncMock, return_value=(1.0, ["a6"])), \
         patch.object(engine, "_layer_ml", new_callable=AsyncMock, return_value=(0.0, True)):
        
        result = await engine.deep_correlate(alert)
        assert result is not None
        assert result["correlated"] is True
        assert result["ml_degraded"] is True
        assert "a2" in result["related_alerts"]
        
        # Test confidence below threshold
        with patch("services.correlation.background_correlator.CONFIDENCE_THRESHOLD", 2.0): # Unreachable
            result2 = await engine.deep_correlate(alert)
            assert result2 is None

# ---------------------------------------------------------------------------
# Incident Handling API
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_handle_correlation_found_create(engine):
    trigger = {"alert_id": "a1", "user": "test"}
    result = {
        "correlated": True,
        "confidence": 0.9,
        "related_alerts": ["a2"],
        "attack_pattern": "phishing",
        "narrative": "test narrative"
    }
    
    engine._db.alerts.find.return_value = [{"alert_id": "a2", "user": "test2"}]
    
    await engine._handle_correlation_found(trigger, result)
    
    engine._incident_tracker.create_incident.assert_called_once()
    args, kwargs = engine._incident_tracker.create_incident.call_args
    assert len(args[0]) == 2 # 2 alert refs (a1, a2)
    assert len(args[1]) == 1 # 1 correlation result
    assert kwargs.get("narrative") == "test narrative"

@pytest.mark.asyncio
async def test_handle_correlation_found_append(engine):
    trigger = {"alert_id": "a1", "user": "test"}
    result = {
        "correlated": True,
        "confidence": 0.9,
        "related_alerts": ["a2"],
        "attack_pattern": "phishing",
        "narrative": "test narrative"
    }
    
    engine._db.alerts.find.return_value = [{"alert_id": "a2", "user": "test2"}]
    engine._incident_tracker.find_incident_by_alerts.return_value = {"incident_id": "inc-123"}
    
    await engine._handle_correlation_found(trigger, result)
    
    engine._incident_tracker.add_alert_to_incident.assert_called_once()
    args, kwargs = engine._incident_tracker.add_alert_to_incident.call_args
    assert args[0] == "inc-123"
