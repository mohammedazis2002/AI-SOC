"""
Tool 7 — MITRE Enrichment Tool
================================
Thin wrapper around MITREEnrichmentService (3-layer pipeline).
Called AFTER the ULF is validated — enrichment requires structured ULF fields
for high-quality semantic embedding in Layer 3.

The MITREEnrichmentService is co-located in this package (moved from enrichment/).
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


async def run_mitre_enrichment(ulf: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tool 7: Run 3-layer MITRE ATT&CK enrichment on a validated ULF.

    Modifies ulf in-place — adds ulf["enrichments"]["mitre"]:
        {
            tactic_id, tactic_name, tactic_shortname,
            technique_id, technique_name, technique_confidence,
            subtechnique_id, subtechnique_name, subtechnique_confidence,
            all_tactics, mapping_method, analyst_review_required,
            platforms, data_sources
        }

    Args:
        ulf: Validated ULF dict (must pass validate_ocsf first)

    Returns:
        Same ulf dict with enrichments.mitre populated.
    """
    from ..mitre_enrichment_service import get_mitre_enrichment_service

    try:
        service = get_mitre_enrichment_service()
        await service.aenrich(ulf)

        enrichment = ulf.get("enrichments", {}).get("mitre", {})
        logger.info(
            f"MITRE: {enrichment.get('technique_id')} "
            f"({enrichment.get('technique_name')}) "
            f"→ tactic={enrichment.get('tactic_id')} "
            f"via {enrichment.get('mapping_method')} "
            f"[conf={enrichment.get('technique_confidence', 0):.2f}]"
        )
    except Exception as e:
        logger.error(f"MITRE enrichment failed: {e}", exc_info=True)
        ulf.setdefault("enrichments", {})
        ulf["enrichments"]["mitre"] = {
            "technique_id": None,
            "technique_name": None,
            "technique_confidence": 0.0,
            "tactic_id": None,
            "tactic_name": "Unknown",
            "mapping_method": "failed",
            "analyst_review_required": True,
            "error": str(e),
        }

    return ulf
