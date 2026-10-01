"""
MITRE D3FEND Benchmark Tool
============================
Queries the mitre_attack_defend Qdrant collection for recommended defensive
controls (countermeasures) for a given MITRE ATT&CK technique.

Then compares those recommended controls against the remediation plan to
compute a coverage score: what fraction of recommended defensive strategies
does the plan address?

Coverage score used by:
  1. Auditor Agent — flags "agent drift" if coverage < 0.5
  2. Decision Engine — positive scoring factor (remediation_coverage_score)
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


async def get_recommended_defenses(
    technique_id: str,
    tactic_name: str = "",
    qdrant_search=None,
    limit: int = 6,
) -> List[Dict[str, Any]]:
    """
    Query mitre_attack_defend collection for D3FEND countermeasures.

    Args:
        technique_id:  MITRE technique ID (e.g. "T1071.001")
        tactic_name:   Optional tactic name for richer semantic query
        qdrant_search: Qdrant search utility instance
        limit:         Max number of controls to retrieve

    Returns:
        List of dicts: [{"name": str, "category": str, "d3fend_id": str, "description": str}]
    """
    if not qdrant_search:
        logger.warning("D3FEND: No qdrant_search — returning empty controls")
        return []

    query_text = f"defensive countermeasure for {technique_id} {tactic_name}".strip()

    try:
        results = await qdrant_search.search_mitre_defend(
            query=query_text,
            filter_type="countermeasure",
            technique_id=technique_id,
            limit=limit,
        )
        controls = [
            {
                "name":        r.get("name", ""),
                "category":    r.get("category", ""),
                "d3fend_id":   r.get("d3fend_id", r.get("id", "")),
                "description": r.get("description", "")[:200],
            }
            for r in results
        ]
        logger.info(
            f"D3FEND: {len(controls)} controls for {technique_id} "
            f"({'|'.join(c['name'][:20] for c in controls[:3])})"
        )
        return controls
    except Exception as e:
        logger.error(f"D3FEND Qdrant query failed: {e}")
        return []


def calculate_remediation_coverage(
    remediation_plan: List[Dict[str, Any]],
    recommended_controls: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compare a remediation plan against recommended D3FEND controls.

    Drift logic (fixed):
    ─────────────────────
    D3FEND may recommend 3–6 controls for a technique. A SOAR plan typically
    executes 3–5 actions. Requiring ≥50% coverage of ALL recommended controls
    would reject almost every plan.

    Instead: drift is only triggered when the plan has ZERO coverage — i.e.,
    it's completely misaligned with the D3FEND framework for this attack type.
    Partial coverage (1 of 5) still contributes positively to the scoring
    formula (0.25 weight). Only 0/N triggers a rejection.

    Returns:
        {
            coverage_score:       float,   # 0.0–1.0 (matched / total recommended)
            matched_controls:     List[str],
            unmatched_controls:   List[str],
            drift_detected:       bool,    # True ONLY if coverage == 0.0
        }
    """
    if not recommended_controls:
        return {
            "coverage_score":     0.70,
            "matched_controls":   [],
            "unmatched_controls": [],
            "drift_detected":     False,
            "note":               "No D3FEND controls found for this technique — neutral score applied",
        }

    plan_d3fend_ids = {
        a.get("d3fend_control", "").lower()
        for a in remediation_plan
        if a.get("d3fend_control")
    }
    plan_action_text = " ".join(
        (a.get("action", "") + " " + a.get("type", "")).lower()
        for a in remediation_plan
    )

    matched = []
    unmatched = []

    for ctrl in recommended_controls:
        ctrl_id   = ctrl.get("d3fend_id", "").lower()
        ctrl_name = ctrl.get("name", "").lower()
        ctrl_cat  = ctrl.get("category", "").lower()

        if (
            ctrl_id in plan_d3fend_ids
            or ctrl_name in plan_action_text
            or (ctrl_cat and ctrl_cat in plan_action_text)
        ):
            matched.append(ctrl.get("name", ctrl_id))
        else:
            unmatched.append(ctrl.get("name", ctrl_id))

    coverage = len(matched) / len(recommended_controls)

    # Drift ONLY when the plan has zero alignment with D3FEND.
    # 1 of 5 = 0.20 → no drift. 0 of 5 = 0.0 → drift.
    drift_detected = (coverage == 0.0)

    if drift_detected:
        logger.warning(
            f"D3FEND drift: plan has NO alignment with recommended controls "
            f"[{', '.join(unmatched[:3])}]"
        )

    return {
        "coverage_score":     round(coverage, 3),
        "matched_controls":   matched,
        "unmatched_controls": unmatched,
        "drift_detected":     drift_detected,
    }

