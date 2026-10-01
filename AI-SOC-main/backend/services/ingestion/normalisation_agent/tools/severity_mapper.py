"""
Tool 5 — Severity Mapper
=========================
Deterministic severity mapping. No LLM.

Maps source-specific severity scores/labels to OCSF SeverityEnum.

Covers:
  - Wazuh rule.level (1–15)
  - SentinelOne confidence/threatLevel
  - CrowdStrike severity (0–100)
  - Generic string labels (critical/high/medium/low/info)
  - Generic numeric fields (0–10 risk scores)
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Wazuh rule.level → OCSF SeverityEnum int ─────────────────────────────────
# Wazuh levels 1–15:
#   1–3  = informational
#   4–6  = low
#   7–10 = medium
#   11–13= high
#   14–15= critical
WAZUH_LEVEL_MAP: Dict[int, int] = {
    1: 1, 2: 1, 3: 1,           # INFORMATIONAL
    4: 2, 5: 2, 6: 2,           # LOW
    7: 3, 8: 3, 9: 3, 10: 3,   # MEDIUM
    11: 4, 12: 4, 13: 4,        # HIGH
    14: 5, 15: 5,               # CRITICAL
}

# ── SentinelOne confidence → SeverityEnum ─────────────────────────────────────
S1_CONFIDENCE_MAP: Dict[str, int] = {
    "malicious":    5,    # CRITICAL
    "suspicious":   4,    # HIGH
    "n/a":          2,    # LOW
    "not_applicable": 2,
}

S1_THREAT_LEVEL_MAP: Dict[str, int] = {
    "critical": 5,
    "high":     4,
    "medium":   3,
    "low":      2,
    "info":     1,
    "unknown":  0,
}

# ── Generic label map ─────────────────────────────────────────────────────────
GENERIC_LABEL_MAP: Dict[str, int] = {
    "critical":      5,
    "crit":          5,
    "high":          4,
    "medium":        3,
    "med":           3,
    "moderate":      3,
    "low":           2,
    "informational": 1,
    "info":          1,
    "notice":        1,
    "unknown":       0,
}

SEVERITY_ID_TO_NAME: Dict[int, str] = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}


def apply_severity_mapping(
    source: Dict[str, Any],
    estimated_source: str,
) -> Dict[str, Any]:
    """
    Tool 5: Map source-specific severity to OCSF SeverityEnum.

    Args:
        source:           Unwrapped alert source dict
        estimated_source: SIEM type from schema_inspector ("wazuh", "sentinelone", etc.)

    Returns:
        {
            "severity_id":  int (0–5, maps to SeverityEnum)
            "severity":     str ("Unknown"/"Informational"/"Low"/"Medium"/"High"/"Critical")
            "raw_severity": str (original source value, for unmapped storage)
        }
    """
    severity_id = 0
    raw_value = None

    rule = source.get("rule") or {}
    data = source.get("data") or {}

    if estimated_source == "wazuh":
        level = rule.get("level")
        if level is not None:
            try:
                level_int = int(level)
                severity_id = WAZUH_LEVEL_MAP.get(level_int, 3)
                raw_value = f"wazuh_level={level_int}"
            except (ValueError, TypeError):
                pass

    elif estimated_source == "sentinelone":
        threat_info = source.get("threatInfo") or {}
        confidence = str(threat_info.get("confidenceLevel", "")).lower()
        threat_level = str(threat_info.get("threatLevel", "")).lower()
        severity_id = (
            S1_CONFIDENCE_MAP.get(confidence)
            or S1_THREAT_LEVEL_MAP.get(threat_level)
            or 3
        )
        raw_value = f"confidence={confidence} level={threat_level}"

    elif estimated_source in ("crowdstrike", "cloudtrail"):
        cs_sev = source.get("severity") or data.get("severity")
        if cs_sev is not None:
            try:
                cs_int = int(float(cs_sev))
                # CrowdStrike 0–100 → OCSF 0–5
                if cs_int >= 80:
                    severity_id = 5
                elif cs_int >= 60:
                    severity_id = 4
                elif cs_int >= 40:
                    severity_id = 3
                elif cs_int >= 20:
                    severity_id = 2
                elif cs_int > 0:
                    severity_id = 1
                raw_value = f"cs_severity={cs_int}"
            except (ValueError, TypeError):
                pass

    # Generic fallback — check common label fields
    if severity_id == 0:
        label_fields = [
            source.get("severity"),
            data.get("severity"),
            rule.get("severity"),
            source.get("level"),
        ]
        for label in label_fields:
            if label:
                mapped = GENERIC_LABEL_MAP.get(str(label).lower().strip())
                if mapped is not None:
                    severity_id = mapped
                    raw_value = str(label)
                    break

    severity_name = SEVERITY_ID_TO_NAME[severity_id]
    logger.debug(
        f"apply_severity_mapping: {estimated_source!r} raw={raw_value!r} "
        f"→ severity_id={severity_id} ({severity_name})"
    )

    return {
        "severity_id": severity_id,
        "severity": severity_name,
        "raw_severity": raw_value,
    }
