"""
Correlation Engine
==================
Dual-mode hybrid correlation:
  - Path B (Quick):      Redis-backed, <5 s, same-user/IP bursts + fast MITRE patterns
  - Path C (Background): Async 6-layer deep correlation with retroactive incident creation

Entry point: HybridCorrelationSystem.handle_alert(alert)
"""

from .hybrid_correlation_system import HybridCorrelationSystem
from .incident_tracker import IncidentTracker
from .models import AlertRef, CorrelationResult, Incident, CorrelationHandleResult

__all__ = [
    "HybridCorrelationSystem",
    "IncidentTracker",
    "AlertRef",
    "CorrelationResult",
    "Incident",
    "CorrelationHandleResult",
]
