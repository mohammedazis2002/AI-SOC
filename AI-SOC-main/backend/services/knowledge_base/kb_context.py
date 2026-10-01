"""
KBContext — Structured result from KBRetrievalService
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class D3FendMeasure:
    """A single D3FEND countermeasure or ATT&CK mitigation."""
    technique_id: str              # D3FEND ID, e.g. "D3-MFA", or MITRE M-ID
    name: str
    category: str                  # Harden / Isolate / Detect / Evict / Deceive
    description: str
    source: str                    # "d3fend" | "attack_mitigation"


@dataclass
class PlaybookResult:
    """A retrieved playbook chunk."""
    playbook_id: str
    title: str
    trigger: str
    mitre_techniques: List[str]
    tactic: str
    steps: List[str]
    d3fend_categories: List[str]
    chunk_type: str               # "summary" | "step"
    mmr_score: float
    similarity_score: float


@dataclass
class IncidentResult:
    """A retrieved historical incident."""
    incident_id: str
    summary: str
    mitre_technique: str
    resolution: str
    outcome: str
    analyst_approved: bool
    timestamp: Optional[float]
    similarity_score: float
    mmr_score: float


@dataclass
class ComplianceControl:
    """A compliance control with parent chain injected (PageIndexRAG)."""
    framework: str
    control_id: str
    control_name: str
    description: str
    parent_chain: List[str]       # ["ISO 27001 > A.9 Access Control > A.9.4 ..."]
    mitre_technique_ids: List[str]
    cia_flags: Dict[str, bool]    # {"confidentiality": True, "integrity": False, ...}
    severity_weight: float
    match_type: str               # "exact" | "semantic" (how it was found)


@dataclass
class KBContext:
    """
    Full knowledge base context assembled for a single alert.
    Passed to Reasoning, Remediation, and Auditor agents.
    """
    # From mitre_attack_defend (direct ID lookup)
    defensive_measures: List[D3FendMeasure] = field(default_factory=list)

    # From playbooks (MMR λ=0.7, top-5 diverse strategies)
    playbooks: List[PlaybookResult] = field(default_factory=list)

    # From historical_incidents (MMR λ=0.6, top-5 diverse past cases)
    similar_incidents: List[IncidentResult] = field(default_factory=list)

    # From compliance_kb (exhaustive audit sweep — ALL applicable controls)
    compliance_controls: List[ComplianceControl] = field(default_factory=list)

    # Metadata
    technique_id: Optional[str] = None
    retrieval_errors: List[str] = field(default_factory=list)

    def compliance_by_framework(self) -> Dict[str, List[ComplianceControl]]:
        """Group compliance controls by framework for structured reporting."""
        grouped: Dict[str, List[ComplianceControl]] = {}
        for ctrl in self.compliance_controls:
            grouped.setdefault(ctrl.framework, []).append(ctrl)
        return grouped

    def has_violations(self) -> bool:
        return len(self.compliance_controls) > 0

    def to_agent_summary(self) -> Dict[str, Any]:
        """Compact dict passed into agent prompts."""
        return {
            "defensive_measures": [
                {"name": m.name, "category": m.category, "description": m.description[:200]}
                for m in self.defensive_measures
            ],
            "playbooks": [
                {"title": p.title, "trigger": p.trigger, "steps": p.steps[:5]}
                for p in self.playbooks
            ],
            "similar_incidents": [
                {"summary": i.summary[:300], "resolution": i.resolution,
                 "mitre": i.mitre_technique, "outcome": i.outcome}
                for i in self.similar_incidents
            ],
            "compliance_violations": {
                fw: [
                    {"control_id": c.control_id, "name": c.control_name,
                     "description": c.description[:200], "parent": " > ".join(c.parent_chain)}
                    for c in ctrls
                ]
                for fw, ctrls in self.compliance_by_framework().items()
            },
        }
