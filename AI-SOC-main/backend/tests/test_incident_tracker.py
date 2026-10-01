"""
Test Incident Tracker
======================
Uses mongomock to simulate MongoDB.

Covers:
  - create_incident stores correct fields and is idempotent
  - add_alert_to_incident updates alert list and severity
  - find_incident_by_alerts retrieves existing incident
  - retroactive update_alert_status_in_mongo links alerts
"""

import asyncio
import sys
from datetime import datetime
from pathlib import Path

import pytest

backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

try:
    import mongomock
    HAS_MONGOMOCK = True
except ImportError:
    HAS_MONGOMOCK = False

skip_no_mongomock = pytest.mark.skipif(
    not HAS_MONGOMOCK,
    reason="mongomock not installed"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert_ref(**overrides):
    from services.correlation.models import AlertRef
    defaults = {
        "alert_id": "a-001",
        "user": "john.doe",
        "source_ip": "10.0.0.1",
        "mitre_technique": "T1566.001",
        "severity": "medium",
        "timestamp": datetime.utcnow(),
    }
    defaults.update(overrides)
    return AlertRef(**defaults)


def _make_corr_result(**overrides):
    from services.correlation.models import CorrelationResult, CorrelationType
    defaults = {
        "correlation_type": CorrelationType.SAME_USER_BURST,
        "confidence": 0.85,
        "related_alert_ids": ["a-001"],
    }
    defaults.update(overrides)
    return CorrelationResult(**defaults)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    if HAS_MONGOMOCK:
        client = mongomock.MongoClient()
        return client["soar_db"]
    else:
        # Fallback: use an in-memory stub
        pytest.skip("mongomock required")


@pytest.fixture
def tracker(mock_db):
    from services.correlation.incident_tracker import IncidentTracker
    return IncidentTracker(db_client=mock_db, redis_client=None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@skip_no_mongomock
class TestCreateIncident:
    def test_creates_incident_and_returns_doc(self, tracker, mock_db):
        ref = _make_alert_ref(alert_id="a-001")
        corr = _make_corr_result()

        result = asyncio.get_event_loop().run_until_complete(
            tracker.create_incident([ref], [corr])
        )

        assert result is not None
        assert result["incident_id"]
        assert result["severity"] in ("critical", "high", "medium", "low")
        assert len(result["alert_refs"]) == 1
        assert result["status"] == "open"

    def test_idempotent_creates_same_id(self, tracker):
        ref = _make_alert_ref(alert_id="a-001")
        corr = _make_corr_result()

        r1 = asyncio.get_event_loop().run_until_complete(
            tracker.create_incident([ref], [corr])
        )
        r2 = asyncio.get_event_loop().run_until_complete(
            tracker.create_incident([ref], [corr])
        )

        # Same alert set → same incident ID
        assert r1["incident_id"] == r2["incident_id"]


@skip_no_mongomock
class TestAddAlertToIncident:
    def test_adds_alert_and_updates(self, tracker):
        ref1 = _make_alert_ref(alert_id="a-001")
        corr = _make_corr_result()
        inc = asyncio.get_event_loop().run_until_complete(
            tracker.create_incident([ref1], [corr])
        )

        ref2 = _make_alert_ref(alert_id="a-002", severity="critical")
        corr2 = _make_corr_result(confidence=0.95, related_alert_ids=["a-001", "a-002"])

        updated = asyncio.get_event_loop().run_until_complete(
            tracker.add_alert_to_incident(inc["incident_id"], ref2, [corr2])
        )

        assert updated is not None
        alert_ids = [r["alert_id"] for r in updated["alert_refs"]]
        assert "a-002" in alert_ids
        # Severity should escalate when critical alert is added
        assert updated["severity"] in ("critical", "high")


@skip_no_mongomock
class TestFindIncident:
    def test_find_existing(self, tracker):
        ref = _make_alert_ref(alert_id="a-001")
        corr = _make_corr_result()
        asyncio.get_event_loop().run_until_complete(
            tracker.create_incident([ref], [corr])
        )

        found = asyncio.get_event_loop().run_until_complete(
            tracker.find_incident_by_alerts(["a-001"])
        )
        assert found is not None
        assert found["incident_id"]

    def test_find_none(self, tracker):
        found = asyncio.get_event_loop().run_until_complete(
            tracker.find_incident_by_alerts(["does-not-exist"])
        )
        assert found is None


@skip_no_mongomock
class TestRetroactiveLink:
    def test_update_alert_status(self, tracker, mock_db):
        # Insert a fake alert doc
        mock_db.alerts.insert_one({"alert_id": "a-001", "status": "open"})

        asyncio.get_event_loop().run_until_complete(
            tracker.update_alert_status_in_mongo("a-001", "INC-ABCD")
        )

        doc = mock_db.alerts.find_one({"alert_id": "a-001"})
        assert doc["incident_id"] == "INC-ABCD"
        assert doc["status"] == "part_of_incident"


@skip_no_mongomock
class TestAuditLog:
    def test_audit_entry_created(self, tracker, mock_db):
        ref = _make_alert_ref(alert_id="a-audit-test")
        corr = _make_corr_result()
        asyncio.get_event_loop().run_until_complete(
            tracker.create_incident([ref], [corr])
        )

        audit = list(mock_db.audit_log.find({"event": "incident_created"}))
        assert len(audit) >= 1
        assert audit[0]["event"] == "incident_created"
