"""
Tool 1 — Schema Inspector
==========================
Structural analysis of a raw alert. Detects nesting, ES export wrapper,
estimates source SIEM type. Deterministic — no LLM.

Output fed to EventClassifier (Tool 2) as the basis for OCSF class selection.
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Known structural signals per SIEM
_WAZUH_SIGNALS = {"rule", "agent", "decoder", "full_log", "predecoder"}
_SENTINELONE_SIGNALS = {"threatInfo", "agentRealtimeInfo", "indicators"}
_CROWDSTRIKE_SIGNALS = {"event_type", "ComputerName", "FalconHostLink"}
_CLOUDTRAIL_SIGNALS = {"eventSource", "awsRegion", "requestParameters"}
_ZSCALER_SIGNALS = {"action", "proto", "rulelabel", "urlsupercat"}


def inspect_schema(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tool 1: Structural schema analysis.

    Args:
        raw_alert: Raw alert dict (any format)

    Returns:
        schema_info dict:
            - is_es_export:       bool — has _index/_id/_source wrapper
            - source:             unwrapped _source dict (or raw_alert)
            - l1_keys:            sorted top-level keys of source
            - l2_keys:            {key: sorted_sub_keys} for nested dicts
            - estimated_source:   "wazuh" | "sentinelone" | "crowdstrike" | "cloudtrail" | "unknown"
            - decoder_name:       decoder.name if present
            - has_mitre_ids:      bool — any T\d{4} strings in the alert
            - has_geo:            bool
            - has_full_log:       bool — raw syslog line present
            - product:            inferred OCSF product dict
            - field_count:        total fields in source
            - nesting_depth:      max nesting depth
    """
    # Unwrap ES export envelope
    is_es_export = "_source" in raw_alert
    source = raw_alert.get("_source", raw_alert) if is_es_export else raw_alert

    l1_keys = sorted(source.keys())
    l2_keys: Dict[str, List[str]] = {}
    for k in l1_keys:
        val = source.get(k)
        if isinstance(val, dict):
            l2_keys[k] = sorted(val.keys())

    # Estimate source SIEM
    source_keys_set = set(l1_keys)
    l2_flat = {k for subs in l2_keys.values() for k in subs}

    estimated_source = "unknown"
    if _WAZUH_SIGNALS.issubset(source_keys_set):
        estimated_source = "wazuh"
    elif _SENTINELONE_SIGNALS & source_keys_set:
        estimated_source = "sentinelone"
    elif _CROWDSTRIKE_SIGNALS & source_keys_set:
        estimated_source = "crowdstrike"
    elif _CLOUDTRAIL_SIGNALS & source_keys_set:
        estimated_source = "cloudtrail"
    elif _ZSCALER_SIGNALS & source_keys_set:
        estimated_source = "zscaler"

    # Decoder name
    decoder_name = ""
    decoder = source.get("decoder")
    if isinstance(decoder, dict):
        decoder_name = decoder.get("name", "")

    # Infer product
    from ..template_cache import _infer_product
    product = _infer_product(decoder_name or estimated_source)

    # MITRE presence check (fast regex over full JSON)
    import re
    alert_str = json.dumps(source, default=str)
    has_mitre_ids = bool(re.search(r"\bT\d{4}(?:\.\d{3})?\b", alert_str))

    # Nesting depth (rough)
    def _depth(obj, d=0):
        if isinstance(obj, dict):
            return max((_depth(v, d + 1) for v in obj.values()), default=d)
        return d

    depth = _depth(source)

    info = {
        "is_es_export": is_es_export,
        "source": source,
        "l1_keys": l1_keys,
        "l2_keys": l2_keys,
        "estimated_source": estimated_source,
        "decoder_name": decoder_name,
        "has_mitre_ids": has_mitre_ids,
        "has_geo": "GeoLocation" in source_keys_set,
        "has_full_log": "full_log" in source_keys_set,
        "product": product,
        "field_count": len(l1_keys),
        "nesting_depth": depth,
    }

    logger.debug(
        f"inspect_schema: source={estimated_source!r} "
        f"decoder={decoder_name!r} fields={len(l1_keys)} depth={depth}"
    )
    return info
