"""Build PlanFeedback-shaped documents from processed alerts (1:1 alert ↔ incident for storage)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.alert_feedback import AlertFeedbackSubmit
from app.services.incidents_service import get_incident_by_alert_id

FEEDBACK_COLLECTION = 'feedback_collection'


def _as_str_list(value: Any) -> list[str] | None:
    if isinstance(value, list) and value and all(isinstance(x, str) for x in value):
        return value
    return None


def _tactic_to_stage(name: Any) -> str:
    if not name or not isinstance(name, str):
        return 'unknown'
    return name.strip().lower().replace(' ', '_').replace('-', '_')


def suggested_original_plan(alert_doc: dict[str, Any], incident_doc: dict[str, Any] | None) -> list[str]:
    """Best-effort AI / system-suggested actions for diff-based learning."""
    if incident_doc:
        ml = incident_doc.get('ml_outputs')
        if isinstance(ml, dict):
            for key in ('recommended_actions', 'suggested_actions', 'response_plan'):
                got = _as_str_list(ml.get(key))
                if got:
                    return got
        report = incident_doc.get('report')
        if isinstance(report, dict):
            for key in ('recommended_actions', 'actions', 'plan'):
                got = _as_str_list(report.get(key))
                if got:
                    return got

    enrich = alert_doc.get('enrichments')
    if isinstance(enrich, dict):
        mitre = enrich.get('mitre')
        if isinstance(mitre, dict):
            for key in ('recommended_actions', 'suggested_remediation', 'remediation_steps'):
                got = _as_str_list(mitre.get(key))
                if got:
                    return got
        rem = enrich.get('remediation')
        if isinstance(rem, dict):
            got = _as_str_list(rem.get('recommended_actions') or rem.get('steps'))
            if got:
                return got

    finding = alert_doc.get('finding') if isinstance(alert_doc.get('finding'), dict) else {}
    title = finding.get('title') or finding.get('desc') or alert_doc.get('alert_id') or 'alert'
    return [f'Investigate and triage: {str(title)[:240]}']


def extract_technique_id(alert_doc: dict[str, Any]) -> str:
    enrich = alert_doc.get('enrichments')
    if isinstance(enrich, dict):
        mitre = enrich.get('mitre')
        if isinstance(mitre, dict) and mitre.get('technique_id'):
            return str(mitre['technique_id']).strip() or 'UNKNOWN'
    if alert_doc.get('technique_id'):
        return str(alert_doc['technique_id']).strip() or 'UNKNOWN'
    return 'UNKNOWN'


def extract_attack_stage(alert_doc: dict[str, Any]) -> str:
    enrich = alert_doc.get('enrichments')
    if isinstance(enrich, dict):
        mitre = enrich.get('mitre')
        if isinstance(mitre, dict):
            stage = _tactic_to_stage(mitre.get('tactic_name'))
            if stage != 'unknown':
                return stage
    return 'unknown'


def incident_created_at(alert_doc: dict[str, Any]) -> datetime:
    for key in ('time', 'ingestion_timestamp', 'processed_at'):
        ts = alert_doc.get(key)
        if hasattr(ts, 'timestamp'):
            if ts.tzinfo is None:
                return ts.replace(tzinfo=UTC)
            return ts.astimezone(UTC)
    return datetime.now(UTC)


def derive_analyst_plan(
    decision: str,
    original_plan: list[str],
    submitted: list[str] | None,
) -> list[str]:
    if decision == 'approve':
        return list(original_plan)
    if decision == 'approve_with_edits':
        if submitted:
            return list(submitted)
        return list(original_plan)
    if decision == 'reject':
        return []
    return list(original_plan) + ['escalate_to_ir']


def plan_diff(original_plan: list[str], analyst_plan: list[str]) -> tuple[list[str], list[str]]:
    a_set = set(analyst_plan)
    removed = [x for x in original_plan if x not in a_set]
    added = [x for x in analyst_plan if x not in set(original_plan)]
    return removed, added


async def build_feedback_document(
    db: AsyncIOMotorDatabase,
    alert_doc: dict[str, Any],
    body: AlertFeedbackSubmit,
    analyst_id: str,
) -> dict[str, Any]:
    incident_id, alert_id = await resolve_incident_id_for_alert(db, alert_doc)
    inc_doc = await get_incident_by_alert_id(db, alert_id)
    original_plan = suggested_original_plan(alert_doc, inc_doc)
    analyst_plan = derive_analyst_plan(body.decision, original_plan, body.analyst_plan)
    removed_actions, added_actions = plan_diff(original_plan, analyst_plan)

    doc: dict[str, Any] = {
        'incident_id': incident_id,
        'alert_id': alert_id,
        'technique_id': extract_technique_id(alert_doc),
        'attack_stage': extract_attack_stage(alert_doc),
        'original_plan': original_plan,
        'analyst_plan': analyst_plan,
        'removed_actions': removed_actions,
        'added_actions': added_actions,
        'decision': body.decision,
        'false_positive': body.false_positive,
        'comment': body.comment,
        'plan_rating': body.plan_rating,
        'analyst_metadata': {
            'analyst_id': analyst_id,
            'team': body.team,
            'confidence': body.confidence,
        },
        'timestamps': {
            'incident_created_at': incident_created_at(alert_doc),
            'feedback_submitted_at': datetime.now(UTC),
        },
        'feedback_source': 'alerts_ui',
    }
    if body.execution_outcome is not None:
        doc['execution_outcome'] = body.execution_outcome.model_dump()
    return doc


async def resolve_incident_id_for_alert(db: AsyncIOMotorDatabase, alert_doc: dict[str, Any]) -> tuple[str, str]:
    """
    Canonical incident_id for feedback (unique per alert when 1:1).
    Prefers agentic incidents.alert.incident_id; otherwise alert_id.
    """
    alert_id = str(
        alert_doc.get('alert_id')
        or alert_doc.get('source_alert_id')
        or alert_doc.get('_id')
        or ''
    )
    inc = await get_incident_by_alert_id(db, alert_id)
    if inc and inc.get('incident_id'):
        return str(inc['incident_id']), alert_id
    return alert_id, alert_id
