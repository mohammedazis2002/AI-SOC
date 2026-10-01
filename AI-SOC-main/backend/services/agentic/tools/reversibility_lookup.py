"""
Reversibility Lookup
====================
Single source of truth for reversibility_tier (1-4), rollback commands,
and risk metadata for any SOAR action type.

All queries go to reversibility_db_full.json — NOT action_catalog.py.

If an action_type is not found in the DB:
  → returns tier 4 (worst-case assumption; no data = assume destructive)

Usage:
    from backend.services.agentic.tools.reversibility_lookup import (
        get_reversibility_tier,
        get_db_entry,
        has_destructive_actions,
    )
"""

import json
import logging
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "../../../data/reversibility_db_full.json"
)


@lru_cache(maxsize=1)
def _load_db() -> Dict[str, Dict[str, Any]]:
    """Load and index reversibility_db_full.json by action_type. Cached."""
    path = os.path.normpath(_DB_PATH)
    try:
        with open(path, encoding="utf-8") as f:
            entries = json.load(f)
        index = {e["action_type"]: e for e in entries}
        logger.info(f"Loaded reversibility DB: {len(index)} entries from {path}")
        return index
    except FileNotFoundError:
        logger.error(f"reversibility_db_full.json not found at {path}")
        return {}
    except Exception as e:
        logger.error(f"Failed to load reversibility DB: {e}")
        return {}


def get_db_entry(action_type: str) -> Optional[Dict[str, Any]]:
    """Return the full DB entry for an action_type, or None if not found."""
    return _load_db().get(action_type)


def get_reversibility_tier(action_type: str) -> int:
    """
    Return reversibility_tier (1-4) for an action_type.

    Tier 1 — Trivial: 1-click undo, no disruption
    Tier 2 — Moderate: manual IT intervention, temporary disruption
    Tier 3 — Destructive: data loss or significant recovery effort
    Tier 4 — Irreversible: permanent structural damage

    If action_type is not in the DB → returns 4 (worst-case).
    """
    entry = get_db_entry(action_type)
    if entry is None:
        logger.warning(
            f"action_type '{action_type}' not found in reversibility DB — defaulting to Tier 4"
        )
        return 4
    tier = entry.get("reversibility_tier", 4)
    if tier not in (1, 2, 3, 4):
        logger.warning(f"Invalid tier {tier} for '{action_type}' — defaulting to 4")
        return 4
    return tier


def get_risk_category(action_type: str) -> str:
    """Return risk_category string ('low'|'medium'|'high'|'critical') from DB."""
    entry = get_db_entry(action_type)
    if entry is None:
        return "high"
    return entry.get("risk_category", "high")


def get_rollback_info(action_type: str) -> Dict[str, Any]:
    """Return rollback method, command, and automated flag from DB."""
    entry = get_db_entry(action_type)
    if entry is None:
        return {
            "rollback_method":    "manual_review",
            "rollback_command":   None,
            "rollback_automated": False,
        }
    return {
        "rollback_method":    entry.get("rollback_method"),
        "rollback_command":   entry.get("rollback_command"),
        "rollback_automated": entry.get("rollback_automated", False),
    }


def get_max_reversibility_tier(actions: List[Dict[str, Any]]) -> int:
    """Return the highest (worst) reversibility_tier across all actions in a plan."""
    tiers = [get_reversibility_tier(a.get("type", "")) for a in actions]
    return max(tiers) if tiers else 1


def has_destructive_actions(actions: List[Dict[str, Any]]) -> bool:
    """True if any action is Tier 3 or Tier 4 (destructive or irreversible)."""
    return get_max_reversibility_tier(actions) >= 3
