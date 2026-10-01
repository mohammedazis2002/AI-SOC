"""
Analyst Feedback Schema - Plan Review and Modifications (feedback loop).

Request body for: POST /api/v1/review/feedback
"""

from pydantic import BaseModel, ConfigDict, Field
from typing import List, Optional, Literal
from datetime import datetime, timezone
from enum import Enum


class DecisionType(str, Enum):
    """Decision types for feedback"""
    APPROVE = "approve"
    APPROVE_WITH_EDITS = "approve_with_edits"
    REJECT = "reject"
    ESCALATE = "escalate"


class AnalystMetadata(BaseModel):
    """Analyst information (required on every submission)."""
    analyst_id: str
    team: str = Field(..., description="Team name, e.g., SOC_L2")
    confidence: Literal["low", "medium", "high"] = "medium"


class ExecutionOutcome(BaseModel):
    """Execution outcome of the response plan (optional)."""
    resolved: bool = Field(..., description="Whether incident was resolved")
    recurrence_within_7_days: bool = Field(default=False)


class Timestamps(BaseModel):
    """Timing for the incident and this feedback event."""
    incident_created_at: datetime
    feedback_submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


_PLAN_FEEDBACK_EXAMPLE = {
    "incident_id": "INC_5821",
    "technique_id": "T1078",
    "attack_stage": "credential_access",
    "original_plan": ["collect_logs", "network_block", "disable_user"],
    "analyst_plan": ["collect_logs", "network_block", "reset_password", "revoke_session"],
    "removed_actions": ["disable_user"],
    "added_actions": ["reset_password", "revoke_session"],
    "decision": "approve_with_edits",
    "plan_rating": 4,
    "false_positive": False,
    "comment": "Reset password safer than disabling user",
    "analyst_metadata": {
        "analyst_id": "analyst_17",
        "team": "SOC_L2",
        "confidence": "high",
    },
    "execution_outcome": {"resolved": True, "recurrence_within_7_days": False},
    "timestamps": {
        "incident_created_at": "2026-03-16T10:10:00Z",
        "feedback_submitted_at": "2026-03-16T10:25:00Z",
    },
}


class PlanFeedback(BaseModel):
    """
    Analyst feedback on an AI-generated incident response plan.

    * **incident_id** — unique per submission; duplicate returns **409**.
    * **false_positive** — if ``true``, document is excluded from learning batches downstream.
    * **plan_rating** / **execution_outcome** — optional per integration contract.
    """

    model_config = ConfigDict(
        json_schema_extra={"examples": [_PLAN_FEEDBACK_EXAMPLE]},
    )

    incident_id: str = Field(..., description="Unique incident id; 409 if feedback already exists")
    alert_id: Optional[str] = Field(
        default=None,
        description="Source alert id when feedback is tied to a single alert (e.g. Alerts UI)",
    )
    technique_id: str = Field(..., description="MITRE ATT&CK technique id, e.g. T1078")
    attack_stage: str = Field(..., description="Kill-chain style stage, e.g. credential_access")

    root_cause_analysis: Optional[dict] = Field(
        default=None,
        description="Optional structured root-cause notes (extension field)",
    )

    original_plan: List[str] = Field(..., description="AI-generated action list")
    analyst_plan: List[str] = Field(..., description="Analyst-approved / edited action list")
    removed_actions: List[str] = Field(
        default_factory=list,
        description="Pre-computed diff vs original (informational)",
    )
    added_actions: List[str] = Field(
        default_factory=list,
        description="Pre-computed diff vs original (informational)",
    )

    decision: DecisionType = Field(..., description="approve | approve_with_edits | reject | escalate")
    plan_rating: Optional[int] = Field(
        default=None,
        ge=1,
        le=5,
        description="Optional 1-5 analyst quality rating",
    )
    false_positive: bool = Field(
        ...,
        description="If true, excluded from learning batch",
    )
    comment: Optional[str] = Field(default=None, description="Free-text analyst notes")

    analyst_metadata: AnalystMetadata
    execution_outcome: Optional[ExecutionOutcome] = Field(
        default=None,
        description="Optional post-execution outcome",
    )
    timestamps: Timestamps


class PlanFeedbackResponse(BaseModel):
    """Response after feedback submission"""
    status: str = "success"
    feedback_id: str
    message: str
