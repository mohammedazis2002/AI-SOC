"""
Tool 6 — OCSF Validator
========================
Validates a candidate ULF dict against the Pydantic UnifiedLogFormat schema.
Returns structured, LLM-readable error messages for retry prompts.
"""

import logging
from typing import Any, Dict, List, Tuple

from pydantic import ValidationError

logger = logging.getLogger(__name__)


def validate_ocsf(candidate: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Tool 6: Validate a candidate dict against the OCSF ULF Pydantic schema.

    Args:
        candidate: Dict to validate

    Returns:
        (valid, errors):
            valid  = True if fully passes Pydantic validation
            errors = List of human-readable error strings (empty if valid)
                     Formatted for direct inclusion in LLM correction prompts.
    """
    from backend.schemas.ulf_schema import UnifiedLogFormat

    try:
        UnifiedLogFormat(**candidate)
        logger.debug("validate_ocsf: PASS")
        return True, []

    except ValidationError as exc:
        errors = _format_errors(exc)
        logger.debug(f"validate_ocsf: FAIL ({len(errors)} errors)")
        return False, errors

    except Exception as exc:
        # Unexpected error (e.g. unhashable type, import error)
        errors = [f"Unexpected validation error: {exc}"]
        logger.warning(f"validate_ocsf unexpected: {exc}")
        return False, errors


def _format_errors(exc: ValidationError) -> List[str]:
    """
    Convert Pydantic v2 ValidationError into clean, LLM-readable strings.

    Example output:
        ["Field 'time': time must be timezone-aware. Supply a UTC datetime object.",
         "Field 'finding.title': Finding title and UID cannot be empty",
         "Field 'alert_id': Invalid alert_id format: 'abc'. Expected format: SOAR-YYYYMMDD-XXXXXXXX"]
    """
    messages = []
    for error in exc.errors():
        loc = " → ".join(str(l) for l in error.get("loc", []))
        msg = error.get("msg", "")
        input_val = error.get("input")

        # Truncate long input values for readability
        if input_val is not None:
            input_str = repr(input_val)
            if len(input_str) > 80:
                input_str = input_str[:77] + "..."
            messages.append(f"Field '{loc}': {msg} (got: {input_str})")
        else:
            messages.append(f"Field '{loc}': {msg}")

    return messages
