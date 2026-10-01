"""
Correlation Engine – Data Models
=================================
Pydantic v2 strict models for all correlation artefacts.

Security notes:
  - strict=True: no silent type coercion
  - All string fields have explicit max_length via Annotated[str, Field(max_length=N)]
  - Use these models as the exclusive data boundary; never pass raw dicts to Redis/Mongo
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class CorrelationType(str, Enum):
    SAME_USER_BURST            = "same_user_burst"
    SAME_IP_BURST              = "same_ip_burst"
    PHISHING_TO_CREDENTIAL     = "phishing_to_credential_theft"
    POWERSHELL_TO_ENCRYPTION   = "powershell_to_encryption"
    TEMPORAL_CLUSTER           = "temporal_cluster"
    ENTITY_LINK                = "entity_link"
    MITRE_CHAIN                = "mitre_chain"
    GRAPH_TRAVERSAL            = "graph_traversal"
    BEHAVIORAL_DEVIATION       = "behavioral_deviation"
    ML_CLUSTER_ANOMALY         = "ml_cluster_anomaly"


class IncidentStatus(str, Enum):
    OPEN       = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED   = "resolved"
    FALSE_POS  = "false_positive"


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


# ---------------------------------------------------------------------------
# Lightweight alert reference (safe to cache in Redis)
# ---------------------------------------------------------------------------

_Str128  = Annotated[str, Field(max_length=128)]
_Str256  = Annotated[str, Field(max_length=256)]
_Str64   = Annotated[str, Field(max_length=64)]


class AlertRef(BaseModel):
    """
    Minimal, scrubbed reference to an alert.
    ONLY these fields are written to Redis — no enrichment data, no secrets.
    """
    model_config = ConfigDict(strict=True)

    alert_id:        _Str128
    user:            Optional[_Str128] = None
    source_ip:       Optional[_Str64]  = None
    mitre_technique: Optional[_Str64]  = None
    severity:        Optional[_Str64]  = None
    timestamp:       datetime          = Field(default_factory=datetime.utcnow)

    def to_cache_dict(self) -> Dict[str, str]:
        """Serialise to flat string dict suitable for Redis HSET."""
        return {
            "alert_id":        self.alert_id,
            "user":            self.user or "",
            "source_ip":       self.source_ip or "",
            "mitre_technique": self.mitre_technique or "",
            "severity":        self.severity or "",
            "timestamp":       self.timestamp.isoformat(),
        }

    @classmethod
    def from_cache_dict(cls, d: Dict[str, str]) -> "AlertRef":
        return cls(
            alert_id=d["alert_id"],
            user=d.get("user") or None,
            source_ip=d.get("source_ip") or None,
            mitre_technique=d.get("mitre_technique") or None,
            severity=d.get("severity") or None,
            timestamp=datetime.fromisoformat(d["timestamp"]),
        )

    @classmethod
    def from_alert(cls, alert: Dict[str, Any]) -> "AlertRef":
        """Extract a safe AlertRef from a raw alert dict."""
        return cls(
            alert_id=str(alert.get("alert_id", "")),
            user=_truncate(
                alert.get("user")
                or alert.get("actor", {}).get("user", {}).get("name")
                or "",
                128,
            ) or None,
            source_ip=_truncate(
                alert.get("source_ip")
                or alert.get("src_endpoint", {}).get("ip")
                or "",
                64,
            ) or None,
            mitre_technique=_truncate(
                _extract_mitre(alert),
                64,
            ) or None,
            severity=_truncate(str(alert.get("severity", "")), 64) or None,
            timestamp=datetime.utcnow(),
        )


# ---------------------------------------------------------------------------
# Correlation result
# ---------------------------------------------------------------------------

class CorrelationResult(BaseModel):
    model_config = ConfigDict(strict=True)

    correlation_type:  CorrelationType
    confidence:        float                        = Field(ge=0.0, le=1.0)
    related_alert_ids: List[_Str128]                = Field(default_factory=list)
    attack_pattern:    Optional[_Str256]            = None
    narrative:         Optional[_Str256]            = None
    layer:             Optional[_Str64]             = None   # which correlation layer found this
    timed_out:         bool                         = False
    degraded:          bool                         = False  # ML layer unavailable


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------

class Incident(BaseModel):
    model_config = ConfigDict(strict=True)

    incident_id:          str                   = Field(default_factory=lambda: str(uuid.uuid4()))
    severity:             IncidentSeverity      = IncidentSeverity.MEDIUM
    status:               IncidentStatus        = IncidentStatus.OPEN
    alert_refs:           List[AlertRef]        = Field(default_factory=list)
    correlation_results:  List[CorrelationResult] = Field(default_factory=list)
    narrative:            Optional[_Str256]     = None
    attack_pattern:       Optional[_Str256]     = None
    confidence:           float                 = Field(default=0.0, ge=0.0, le=1.0)
    created_at:           datetime              = Field(default_factory=datetime.utcnow)
    updated_at:           datetime              = Field(default_factory=datetime.utcnow)
    resolved_at:          Optional[datetime]    = None
    analyst_notes:        Optional[_Str256]     = None


# ---------------------------------------------------------------------------
# Top-level handle result returned by HybridCorrelationSystem
# ---------------------------------------------------------------------------

class CorrelationHandleResult(BaseModel):
    model_config = ConfigDict(strict=False)   # relaxed – internal use only

    alert_id:            str
    quick_correlations:  List[CorrelationResult]    = Field(default_factory=list)
    incident_id:         Optional[str]              = None   # set if quick corr created/updated incident
    deep_queued:         bool                       = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _truncate(value: str, max_len: int) -> str:
    return value[:max_len] if value else ""


def _extract_mitre(alert: Dict[str, Any]) -> str:
    """Best-effort extraction of primary MITRE technique ID from alert."""
    # Direct field
    if alert.get("mitre_technique"):
        return str(alert["mitre_technique"])
    # Enrichment path
    enrichments = alert.get("enrichments", {})
    mitre = enrichments.get("mitre", {})
    if mitre.get("technique_id"):
        return str(mitre["technique_id"])
    # OCSF attack field
    attacks = alert.get("attacks", [])
    if attacks and isinstance(attacks, list):
        first = attacks[0]
        techs = first.get("technique", {})
        return str(techs.get("uid", ""))
    return ""
