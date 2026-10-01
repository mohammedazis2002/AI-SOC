"""
ML Trigger Tool
===============
Determines whether to call the RCA (Root Cause Analysis) and Attack Stage
Predictor ML services for a given alert.

Rules:
  - severity_id == 5 (CRITICAL): ALWAYS call RCA + Attack Stage regardless of anomaly_score
  - severity_id == 4 (HIGH) AND anomaly_score > 0.60: call RCA + Attack Stage
  - Otherwise: skip ML services (faster path)

This is deterministic — no LLM.

NOTE: anomaly_score must come from state["ml_outputs"]["anomaly_detection"]["anomaly_score"],
      NOT from alert["fp_analysis"]. The Anomaly Detection model runs before the agentic
      pipeline and populates this value.
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Thresholds
SEVERITY_CRITICAL  = 5       # CRITICAL (OCSF SeverityEnum) — always fires
SEVERITY_HIGH      = 4       # HIGH — fires only if anomaly_score also passes
ANOMALY_THRESHOLD  = 0.60    # anomaly_score from Anomaly Detection model (0–1)


def should_call_ml_services(
    alert: Dict[str, Any],
    anomaly_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Determine whether to call RCA and Attack Stage Predictor.

    Args:
        alert:         Enriched ULF alert dict
        anomaly_score: Score from Anomaly Detection ML model (state["ml_outputs"]["anomaly_detection"]["anomaly_score"]).
                       Defaults to 0.0 if not provided (safe — avoids false triggers).

    Returns:
        {
            call_rca:           bool,
            call_attack_stage:  bool,
            services:           List[str],
            trigger_reason:     str,
            anomaly_score:      float,
            severity_id:        int,
        }
    """
    severity_id   = int(alert.get("severity_id", 0))
    severity_name = alert.get("severity", "unknown")

    is_critical   = severity_id >= SEVERITY_CRITICAL
    is_high       = severity_id == SEVERITY_HIGH
    high_anomaly  = anomaly_score > ANOMALY_THRESHOLD

    # CRITICAL always fires; HIGH fires only with high anomaly
    trigger = is_critical or (is_high and high_anomaly)
    services: List[str] = []

    if trigger:
        services = ["rca", "attack_stage"]
        if is_critical:
            reason = (
                f"Triggered (CRITICAL override): severity_id={severity_id} ({severity_name}) "
                f"— CRITICAL alerts always call RCA + Attack Stage"
            )
        else:
            reason = (
                f"Triggered: severity_id={severity_id} ({severity_name}) ≥ {SEVERITY_HIGH} "
                f"AND anomaly_score={anomaly_score:.3f} > {ANOMALY_THRESHOLD}"
            )
        logger.info(f"ML trigger: FIRE — {reason}")
    else:
        reasons = []
        if not is_critical and not is_high:
            reasons.append(f"severity_id={severity_id} < {SEVERITY_HIGH}")
        if is_high and not high_anomaly:
            reasons.append(f"anomaly_score={anomaly_score:.3f} ≤ {ANOMALY_THRESHOLD}")
        reason = "Not triggered: " + "; ".join(reasons)
        logger.info(f"ML trigger: SKIP — {reason}")

    return {
        "call_rca":          trigger,
        "call_attack_stage": trigger,
        "services":          services,
        "trigger_reason":    reason,
        "anomaly_score":     anomaly_score,
        "severity_id":       severity_id,
    }
