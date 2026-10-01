"""Request body for POST /alerts/{alert_id}/feedback."""

from typing import Literal

from pydantic import BaseModel, Field


class ExecutionOutcomeIn(BaseModel):
    resolved: bool
    recurrence_within_7_days: bool = False


class AlertFeedbackSubmit(BaseModel):
    decision: Literal['approve', 'approve_with_edits', 'reject', 'escalate']
    false_positive: bool
    comment: str | None = Field(None, max_length=20_000)
    plan_rating: int | None = Field(None, ge=1, le=5)
    analyst_plan: list[str] | None = Field(
        None,
        description='Required semantics: for approve_with_edits, send the final action list; omit for approve',
    )
    team: str = Field('SOC', min_length=1, max_length=128)
    confidence: Literal['low', 'medium', 'high'] = 'medium'
    execution_outcome: ExecutionOutcomeIn | None = None
