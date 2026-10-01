"""
Enhanced Data Models for Asset Risk Evaluation

Comprehensive dataclasses for profiles, exposure, vulnerabilities, and threat intelligence.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum

from .enums import ComprehensiveAssetType, Industry, Criticality, DataClassification


# =================================================================
# Asset Profile
# =================================================================

@dataclass
class AssetProfile:
    """
    Complete asset profile with all risk-related metadata.
    """
    # Identity
    asset_id: str
    hostname: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    
    # Classification
    asset_type: ComprehensiveAssetType = ComprehensiveAssetType.UNKNOWN
    industry: Industry = Industry.IT_SERVICES
    criticality: Criticality = Criticality.MEDIUM
    data_classification: DataClassification = DataClassification.INTERNAL
    
    # Environment
    environment: str = "production"  # production, staging, development
    department: Optional[str] = None
    owner: Optional[str] = None
    
    # Compliance Flags (from compliance_detector)
    has_pci_data: bool = False
    has_pii: bool = False
    has_phi: bool = False
    
    # Operating System
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_edition: Optional[str] = None
    
    # Metadata
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# =================================================================
# Vulnerability Data
# =================================================================

@dataclass
class VulnerabilityData:
    """
    Aggregated vulnerability information for an asset.
    """
    # Counts by severity
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Aging metrics
    oldest_unpatched_days: int = 0
    avg_days_to_patch: int = 0
    
    # Specific vulnerability flags
    has_rce_vulnerabilities: bool = False
    has_known_exploits: bool = False
    has_public_exploits: bool = False
    
    # Source metadata
    source: str = "alert"  # alert, inventory, nvd
    last_scanned: Optional[datetime] = None
    scan_id: Optional[str] = None
    
    # Detailed CVE list (optional)
    cve_list: List[Dict] = field(default_factory=list)
    
    def total_count(self) -> int:
        """Total vulnerability count."""
        return (self.critical_count + self.high_count + 
                self.medium_count + self.low_count)


# =================================================================
# Exposure Data
# =================================================================

@dataclass
class ComprehensiveExposureData:
    """
    Comprehensive attack surface data (34 factors).
    """
    
    # ═══════════════════════════════════════════════════════
    # Network Zone (4 factors)
    # ═══════════════════════════════════════════════════════
    internet_facing: bool = False
    in_dmz: bool = False
    internal_only: bool = True
    isolated: bool = False
    
    # ═══════════════════════════════════════════════════════
    # Port Exposure (1 factor - dynamic)
    # ═══════════════════════════════════════════════════════
    open_ports: List[int] = field(default_factory=list)
    
    # ═══════════════════════════════════════════════════════
    # Access & Privileges (2 factors)
    # ═══════════════════════════════════════════════════════
    has_privileged_access: bool = False
    is_service_account: bool = False
    
    # ═══════════════════════════════════════════════════════
    # Lateral Movement (3 factors)
    # ═══════════════════════════════════════════════════════
    can_access_critical_assets: bool = False
    has_cached_credentials: bool = False
    is_domain_joined: bool = False
    
    # ═══════════════════════════════════════════════════════
    # Vulnerability Exposure (3 factors)
    # ═══════════════════════════════════════════════════════
    has_rce_vulnerabilities: bool = False
    has_known_exploits: bool = False
    has_public_exploits: bool = False
    
    # ═══════════════════════════════════════════════════════
    # Geo-Risk (2 factors)
    # ═══════════════════════════════════════════════════════
    accessible_from_high_risk_geo: bool = False
    has_tor_access: bool = False
    
    # ═══════════════════════════════════════════════════════
    # Encryption & Data Protection (3 factors)
    # ═══════════════════════════════════════════════════════
    has_encryption_at_rest: bool = False
    has_encryption_in_transit: bool = False
    uses_weak_protocols: bool = False
    
    # ═══════════════════════════════════════════════════════
    # Authentication & Access Control (3 factors)
    # ═══════════════════════════════════════════════════════
    has_mfa_enabled: bool = False
    uses_weak_auth: bool = False
    password_policy_strength: int = 0  # 0-100
    
    # ═══════════════════════════════════════════════════════
    # Patch Management (2 factors)
    # ═══════════════════════════════════════════════════════
    avg_days_to_patch: int = 0
    has_automatic_updates: bool = False
    
    # ═══════════════════════════════════════════════════════
    # Network Segmentation (3 factors)
    # ═══════════════════════════════════════════════════════
    is_micro_segmented: bool = False
    vlan_count: int = 0
    firewall_rule_count: int = 0
    
    # ═══════════════════════════════════════════════════════
    # Monitoring & Protection (3 factors)
    # ═══════════════════════════════════════════════════════
    has_edr_agent: bool = False
    has_siem_coverage: bool = False
    has_ids_ips: bool = False
    
    # ═══════════════════════════════════════════════════════
    # Backup & Recovery (3 factors)
    # ═══════════════════════════════════════════════════════
    has_recent_backup: bool = False
    days_since_backup: int = 999
    has_tested_recovery: bool = False
    
    # ═══════════════════════════════════════════════════════
    # Configuration Security (3 factors)
    # ═══════════════════════════════════════════════════════
    has_default_credentials: bool = False
    has_unnecessary_services: bool = False
    security_config_score: int = 0  # 0-100 from CIS benchmarks
    
    # ═══════════════════════════════════════════════════════
    # Cloud-Specific (3 factors)
    # ═══════════════════════════════════════════════════════
    has_public_s3_bucket: bool = False
    has_overly_permissive_iam: bool = False
    has_security_groups: bool = True
    
    # ═══════════════════════════════════════════════════════
    # Historical Context (2 factors)
    # ═══════════════════════════════════════════════════════
    was_previously_compromised: bool = False
    days_since_last_compromise: Optional[int] = None


# =================================================================
# Incident History Data
# =================================================================

@dataclass
class IncidentHistoryData:
    """
    Historical incident data for time-decay scoring.
    """
    # Counts by severity
    critical_incidents: int = 0
    high_incidents: int = 0
    medium_incidents: int = 0
    low_incidents: int = 0
    
    # Most recent incident
    most_recent_incident_date: Optional[datetime] = None
    most_recent_severity: Optional[str] = None
    
    # Time window
    window_days: int = 90
    
    # Recidivism flag
    is_repeat_offender: bool = False
    
    def total_count(self) -> int:
        """Total incident count."""
        return (self.critical_incidents + self.high_incidents + 
                self.medium_incidents + self.low_incidents)


# =================================================================
# Threat Intelligence Data
# =================================================================

@dataclass
class ThoroughThreatIntelData:
    """
    Exhaustive threat intelligence data (27 variables).
    """
    
    # ═══════════════════════════════════════════════════════
    # OTX (AlienVault) - 6 variables
    # ═══════════════════════════════════════════════════════
    in_active_campaign: bool = False
    campaign_name: str = ""
    campaign_severity: str = ""  # low/medium/high/critical
    asset_type_targeted: List[str] = field(default_factory=list)
    industry_under_attack: List[str] = field(default_factory=list)
    threat_actor_name: str = ""
    
    # ═══════════════════════════════════════════════════════
    # VirusTotal - 4 variables
    # ═══════════════════════════════════════════════════════
    vt_malicious_count: int = 0
    vt_suspicious_count: int = 0
    vt_reputation_score: int = 0  # -100 to +100
    vt_community_votes: Dict[str, int] = field(default_factory=dict)
    
    # ═══════════════════════════════════════════════════════
    # AbuseIPDB - 5 variables
    # ═══════════════════════════════════════════════════════
    abuse_confidence_score: int = 0  # 0-100
    abuse_report_count: int = 0
    abuse_categories: List[str] = field(default_factory=list)
    abuse_last_reported: Optional[datetime] = None
    abuse_is_whitelisted: bool = False
    
    # ═══════════════════════════════════════════════════════
    # GeoIP - 7 variables
    # ═══════════════════════════════════════════════════════
    source_country: str = ""
    source_country_risk_score: int = 0  # 0-100
    is_tor_exit_node: bool = False
    is_anonymous_proxy: bool = False
    is_vpn: bool = False
    is_hosting_provider: bool = False
    is_mobile_network: bool = False
    
    # ═══════════════════════════════════════════════════════
    # TTP & Pattern Matching - 5 variables
    # ═══════════════════════════════════════════════════════
    matches_known_ttp: bool = False
    matched_ttp_ids: List[str] = field(default_factory=list)
    ttp_confidence_score: float = 0.0
    is_targeted_attack: bool = False
    attack_sophistication: str = ""  # low/medium/high/advanced_persistent


# =================================================================
# Risk Calculation Result
# =================================================================

class RiskLevel(Enum):
    """Risk level categorization."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class RiskCalculationResult:
    """
    Complete risk calculation result with breakdown.
    """
    # Overall Score
    total_risk_score: float
    risk_level: RiskLevel
    
    # Factor Scores (0-100 each)
    criticality_score: float
    vulnerability_score: float
    exposure_score: float
    incident_history_score: float
    threat_intel_score: float
    
    # Factor Contributions (weighted)
    criticality_contribution: float
    vulnerability_contribution: float
    exposure_contribution: float
    incident_contribution: float
    threat_intel_contribution: float
    
    # Metadata
    calculated_at: datetime
    asset_id: str
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    top_risk_factors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API response."""
        return {
            "total_risk_score": round(self.total_risk_score, 2),
            "risk_level": self.risk_level.value,
            "factor_scores": {
                "criticality": round(self.criticality_score, 2),
                "vulnerability": round(self.vulnerability_score, 2),
                "exposure": round(self.exposure_score, 2),
                "incident_history": round(self.incident_history_score, 2),
                "threat_intelligence": round(self.threat_intel_score, 2)
            },
            "factor_contributions": {
                "criticality": round(self.criticality_contribution, 2),
                "vulnerability": round(self.vulnerability_contribution, 2),
                "exposure": round(self.exposure_contribution, 2),
                "incident_history": round(self.incident_contribution, 2),
                "threat_intelligence": round(self.threat_intel_contribution, 2)
            },


            
            "calculated_at": self.calculated_at.isoformat(),
            "asset_id": self.asset_id,
            "recommendations": self.recommendations,
            "top_risk_factors": self.top_risk_factors
        }
