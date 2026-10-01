"""Role → manual-review tier visibility (Mongo `incidents`, decision MANUAL_REVIEW)."""

from __future__ import annotations

INCIDENTS_COLLECTION = 'incidents'


def can_see_unmapped_tab(role_name: str | None, is_superadmin: bool) -> bool:
    return bool(is_superadmin or role_name in ('Admin', 'Engineer'))


def manual_review_tiers_for_role(role_name: str | None, is_superadmin: bool) -> list[str] | None:
    """Mongo `final_tier` filter. None = all tiers. [] = no manual-review queue for this role."""
    if is_superadmin or role_name == 'Admin':
        return None
    if role_name == 'Engineer':
        return []
    if role_name == 'L1':
        return ['l1']
    if role_name == 'L2':
        return ['l2']
    if role_name == 'L3':
        return ['l3', 'ir']
    return []


def allowed_escalation_targets(from_tier: str) -> list[str]:
    t = (from_tier or '').lower()
    if t == 'l1':
        return ['l2']
    if t == 'l2':
        return ['l3', 'ir']
    if t == 'l3':
        return ['ir']
    return []


def user_may_escalate_incident(role_name: str | None, is_superadmin: bool, current_tier: str) -> bool:
    if not allowed_escalation_targets(current_tier):
        return False
    if is_superadmin or role_name == 'Admin':
        return True
    ct = (current_tier or '').lower()
    if role_name == 'L1' and ct == 'l1':
        return True
    if role_name == 'L2' and ct == 'l2':
        return True
    if role_name == 'L3' and ct == 'l3':
        return True
    return False
