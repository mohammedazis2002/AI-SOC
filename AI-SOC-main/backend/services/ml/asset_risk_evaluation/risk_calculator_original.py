"""
Asset Risk Calculator - Core Risk Scoring Algorithm

Risk Score (0-100) calculated from 5 weighted factors:
- Criticality (25%): Business impact of the asset
- Vulnerabilities (30%): Known CVE/CVSS weaknesses
- Exposure (20%): Network attack surface
- Incident History (15%): Past compromises (90-day decay)
- Threat Intel (10%): Active targeting intelligence

Weight Justifications (Industry Research):
- Vulnerabilities (30%): CVSS is the NIST/NVD primary metric. ~60% of breaches
  exploit known CVEs (Verizon DBIR). Most objective, measurable factor.
- Criticality (25%): FAIR framework - Loss Magnitude correlates with asset
  criticality. Business context drives prioritization decisions.
- Exposure (20%): OWASP methodology factors in "Ease of Discovery" and
  "Opportunity". Internet-facing assets are 3-5x more likely to be attacked.
- Incident History (15%): Recidivism factor - assets with prior incidents are
  statistically more likely to be targeted again. MITRE recommends tracking.
- Threat Intel (10%): Lower weight because intel can be lagging/unreliable,
  but active campaigns warrant immediate attention.

These weights are CONFIGURABLE per organization's risk appetite.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import math


class RiskLevel(str, Enum):
    """Risk level classifications based on score thresholds."""
    CRITICAL = "critical"  # 80-100
    HIGH = "high"          # 60-79
    MEDIUM = "medium"      # 40-59
    LOW = "low"            # 0-39


class AssetType(str, Enum):
    """Asset type classifications."""
    SERVER = "server"
    ENDPOINT = "endpoint"
    NETWORK_DEVICE = "network_device"
    CLOUD_RESOURCE = "cloud_resource"
    DATABASE = "database"
    CONTAINER = "container"


class Criticality(str, Enum):
    """Asset criticality levels."""
    CRITICAL = "critical"  # Domain controllers, payment systems
    HIGH = "high"          # Application servers, file servers
    MEDIUM = "medium"      # Workstations, printers
    LOW = "low"            # Guest devices, IoT, test systems


class DataClassification(str, Enum):
    """Data sensitivity classification."""
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"


@dataclass
class VulnerabilityData:
    """Vulnerability data for an asset."""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    oldest_unpatched_days: int = 0
    
    @property
    def total_count(self) -> int:
        return self.critical_count + self.high_count + self.medium_count + self.low_count


@dataclass
class ExposureData:
    """Network exposure data for an asset."""
    internet_facing: bool = False
    in_dmz: bool = False
    internal_only: bool = True
    isolated: bool = False
    open_port_count: int = 0
    has_privileged_access: bool = False


@dataclass
class IncidentData:
    """Incident history for an asset (last 90 days)."""
    critical_incidents: int = 0
    high_incidents: int = 0
    medium_incidents: int = 0
    low_incidents: int = 0
    days_since_last_incident: Optional[int] = None


@dataclass
class ThreatIntelData:
    """Threat intelligence data for an asset."""
    in_active_campaign: bool = False
    asset_type_targeted: bool = False
    industry_under_attack: bool = False
    has_generic_threats: bool = False


@dataclass
class AssetProfile:
    """Complete asset profile for risk calculation."""
    asset_id: str
    hostname: str
    ip_address: str
    asset_type: AssetType
    criticality: Criticality
    department: str = ""
    function: str = ""
    data_classification: DataClassification = DataClassification.INTERNAL
    
    # Risk factor data
    vulnerabilities: VulnerabilityData = field(default_factory=VulnerabilityData)
    exposure: ExposureData = field(default_factory=ExposureData)
    incidents: IncidentData = field(default_factory=IncidentData)
    threat_intel: ThreatIntelData = field(default_factory=ThreatIntelData)


@dataclass
class RiskFactorResult:
    """Result of scoring a single risk factor."""
    name: str
    score: float           # 0-100 raw score
    weighted_score: float  # score * weight
    weight: float          # Factor weight (0-1)
    reason: str            # Explanation


@dataclass
class RiskResult:
    """Complete risk assessment result."""
    asset_id: str
    risk_score: float           # 0-100
    risk_level: RiskLevel
    factors: Dict[str, Dict]    # Factor breakdown
    primary_driver: str         # Highest contributing factor
    recommendations: List[str]  # Actionable recommendations
    calculated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "asset_id": self.asset_id,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level.value,
            "factors": self.factors,
            "primary_driver": self.primary_driver,
            "recommendations": self.recommendations,
            "calculated_at": self.calculated_at.isoformat()
        }


class AssetRiskCalculator:
    """
    Asset Risk Calculator - Evaluates risk on a 0-100 scale.
    
    Uses 5 weighted factors with industry-backed justifications:
    - Vulnerabilities (30%): CVSS-based, most objective metric
    - Criticality (25%): Business impact per FAIR framework
    - Exposure (20%): Attack surface per OWASP methodology
    - Incident History (15%): Recidivism factor with decay
    - Threat Intel (10%): Active targeting intelligence
    """
    
    # Default weights (sum to 1.0 = 100%)
    # These are backed by industry research (see module docstring)
    DEFAULT_WEIGHTS = {
        "criticality": 0.25,      # Business impact
        "vulnerabilities": 0.30,  # Known weaknesses
        "exposure": 0.20,         # Attack surface
        "incident_history": 0.15, # Past compromises
        "threat_intel": 0.10,     # Active targeting
    }
    
    # Criticality score mapping (0-100)
    CRITICALITY_SCORES = {
        Criticality.CRITICAL: 100,
        Criticality.HIGH: 75,
        Criticality.MEDIUM: 50,
        Criticality.LOW: 25,
    }
    
    # Risk level thresholds
    RISK_THRESHOLDS = {
        "critical": 80,
        "high": 60,
        "medium": 40,
        "low": 0,
    }
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Initialize calculator with optional custom weights.
        
        Args:
            weights: Custom weights dict. Must sum to 1.0.
                     Keys: criticality, vulnerabilities, exposure, 
                           incident_history, threat_intel
        """
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self._validate_weights()
    
    def _validate_weights(self):
        """Ensure weights are valid and sum to 1.0."""
        total = sum(self.weights.values())
        if not (0.99 <= total <= 1.01):  # Allow small float error
            raise ValueError(f"Weights must sum to 1.0, got {total}")
        
        required_keys = set(self.DEFAULT_WEIGHTS.keys())
        if set(self.weights.keys()) != required_keys:
            raise ValueError(f"Missing weight keys: {required_keys - set(self.weights.keys())}")
    
    def calculate_risk(self, profile: AssetProfile) -> RiskResult:
        """
        Calculate the overall risk score for an asset.
        
        Args:
            profile: Complete asset profile with all risk factor data.
            
        Returns:
            RiskResult with score, level, and breakdown.
        """
        factors: List[RiskFactorResult] = []
        
        # Score each factor
        factors.append(self._score_criticality(profile))
        factors.append(self._score_vulnerabilities(profile))
        factors.append(self._score_exposure(profile))
        factors.append(self._score_incident_history(profile))
        factors.append(self._score_threat_intel(profile))
        
        # Calculate weighted total
        total_score = sum(f.weighted_score for f in factors)
        
        # Clamp to 0-100
        total_score = max(0, min(100, total_score))
        
        # Determine risk level
        risk_level = self._get_risk_level(total_score)
        
        # Find primary driver
        primary = max(factors, key=lambda f: f.weighted_score)
        
        # Build factor breakdown dict
        factors_dict = {
            f.name: {
                "raw_score": round(f.score, 1),
                "weight": f"{int(f.weight * 100)}%",
                "weighted_score": round(f.weighted_score, 1),
                "reason": f.reason
            }
            for f in factors
        }
        
        # Generate recommendations
        recommendations = self._generate_recommendations(factors, risk_level)
        
        return RiskResult(
            asset_id=profile.asset_id,
            risk_score=total_score,
            risk_level=risk_level,
            factors=factors_dict,
            primary_driver=primary.name,
            recommendations=recommendations
        )
    
    # =========================================================================
    # Individual Factor Scoring
    # =========================================================================
    
    def _score_criticality(self, profile: AssetProfile) -> RiskFactorResult:
        """
        Score based on asset criticality (business impact).
        
        Justification: FAIR framework - Loss Magnitude correlates directly
        with asset criticality. Critical assets warrant higher risk scores.
        """
        score = self.CRITICALITY_SCORES.get(profile.criticality, 50)
        weight = self.weights["criticality"]
        
        reason = f"Asset criticality: {profile.criticality.value}"
        if profile.function:
            reason += f" ({profile.function})"
        
        return RiskFactorResult(
            name="criticality",
            score=score,
            weighted_score=score * weight,
            weight=weight,
            reason=reason
        )
    
    def _score_vulnerabilities(self, profile: AssetProfile) -> RiskFactorResult:
        """
        Score based on known vulnerabilities (CVE/CVSS data).
        
        Formula: (critical * 25) + (high * 15) + (medium * 5) + (low * 1)
        Capped at 100.
        
        Justification: CVSS is the NIST/NVD primary metric. Studies show
        ~60% of breaches exploit known CVEs. Most objective metric.
        """
        vuln = profile.vulnerabilities
        weight = self.weights["vulnerabilities"]
        
        # Weighted vulnerability count
        raw_score = (
            (vuln.critical_count * 25) +
            (vuln.high_count * 15) +
            (vuln.medium_count * 5) +
            (vuln.low_count * 1)
        )
        
        # Cap at 100
        score = min(100, raw_score)
        
        # Add bonus for old unpatched vulns (stale patches are worse)
        if vuln.oldest_unpatched_days > 90:
            score = min(100, score + 10)
        
        reason = f"{vuln.total_count} vulnerabilities "
        reason += f"(C:{vuln.critical_count} H:{vuln.high_count} M:{vuln.medium_count} L:{vuln.low_count})"
        
        return RiskFactorResult(
            name="vulnerabilities",
            score=score,
            weighted_score=score * weight,
            weight=weight,
            reason=reason
        )
    
    def _score_exposure(self, profile: AssetProfile) -> RiskFactorResult:
        """
        Score based on network exposure (attack surface).
        
        Components:
        - Internet-facing: +40
        - DMZ: +30
        - Internal: +10
        - Isolated: 0
        - Open ports: +(count * 2), max 20
        - Privileged access: +20
        
        Justification: OWASP factors in "Ease of Discovery" and "Opportunity".
        Internet-facing assets are 3-5x more likely to be attacked (Verizon DBIR).
        """
        exp = profile.exposure
        weight = self.weights["exposure"]
        
        score = 0
        reasons = []
        
        # Network zone scoring
        if exp.internet_facing:
            score += 40
            reasons.append("Internet-facing")
        elif exp.in_dmz:
            score += 30
            reasons.append("In DMZ")
        elif exp.internal_only:
            score += 10
            reasons.append("Internal network")
        elif exp.isolated:
            score += 0
            reasons.append("Isolated")
        
        # Open ports
        port_score = min(20, exp.open_port_count * 2)
        if port_score > 0:
            score += port_score
            reasons.append(f"{exp.open_port_count} open ports")
        
        # Privileged access
        if exp.has_privileged_access:
            score += 20
            reasons.append("Privileged access")
        
        # Cap at 100
        score = min(100, score)
        
        reason = ", ".join(reasons) if reasons else "No exposure data"
        
        return RiskFactorResult(
            name="exposure",
            score=score,
            weighted_score=score * weight,
            weight=weight,
            reason=reason
        )
    
    def _score_incident_history(self, profile: AssetProfile) -> RiskFactorResult:
        """
        Score based on incident history (last 90 days with decay).
        
        Formula: (critical * 30) + (high * 20) + (medium * 10) + (low * 5)
        Applied with time decay factor.
        
        Justification: Recidivism factor - assets with prior incidents are
        statistically more likely to be targeted again. MITRE ATT&CK
        recommends tracking historical attack patterns.
        """
        inc = profile.incidents
        weight = self.weights["incident_history"]
        
        # Raw incident score
        raw_score = (
            (inc.critical_incidents * 30) +
            (inc.high_incidents * 20) +
            (inc.medium_incidents * 10) +
            (inc.low_incidents * 5)
        )
        
        # Apply decay factor based on time since last incident
        # Decay: 1.0 if recent, decreasing over 90 days
        if inc.days_since_last_incident is None:
            decay = 0.5  # No incident history - neutral
        elif inc.days_since_last_incident <= 7:
            decay = 1.0  # Very recent
        elif inc.days_since_last_incident <= 30:
            decay = 0.8
        elif inc.days_since_last_incident <= 60:
            decay = 0.6
        elif inc.days_since_last_incident <= 90:
            decay = 0.4
        else:
            decay = 0.2  # Old incidents matter less
        
        score = min(100, raw_score * decay)
        
        total_incidents = (inc.critical_incidents + inc.high_incidents + 
                          inc.medium_incidents + inc.low_incidents)
        
        if total_incidents > 0:
            reason = f"{total_incidents} incidents in 90 days"
            if inc.days_since_last_incident is not None:
                reason += f" (last: {inc.days_since_last_incident}d ago)"
        else:
            reason = "No recent incidents"
        
        return RiskFactorResult(
            name="incident_history",
            score=score,
            weighted_score=score * weight,
            weight=weight,
            reason=reason
        )
    
    def _score_threat_intel(self, profile: AssetProfile) -> RiskFactorResult:
        """
        Score based on threat intelligence.
        
        Components:
        - In active campaign: 100
        - Asset type targeted: 75
        - Industry under attack: 50
        - Generic threats: 25
        
        Justification: Lower weight (10%) because threat intel can be
        lagging and less reliable than concrete vulnerability data.
        However, active campaigns warrant immediate attention.
        """
        ti = profile.threat_intel
        weight = self.weights["threat_intel"]
        
        if ti.in_active_campaign:
            score = 100
            reason = "Asset in active threat campaign"
        elif ti.asset_type_targeted:
            score = 75
            reason = f"Asset type ({profile.asset_type.value}) actively targeted"
        elif ti.industry_under_attack:
            score = 50
            reason = "Industry under active attack"
        elif ti.has_generic_threats:
            score = 25
            reason = "Generic threat indicators present"
        else:
            score = 0
            reason = "No active threat intelligence"
        
        return RiskFactorResult(
            name="threat_intel",
            score=score,
            weighted_score=score * weight,
            weight=weight,
            reason=reason
        )
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _get_risk_level(self, score: float) -> RiskLevel:
        """Map score to risk level."""
        if score >= self.RISK_THRESHOLDS["critical"]:
            return RiskLevel.CRITICAL
        elif score >= self.RISK_THRESHOLDS["high"]:
            return RiskLevel.HIGH
        elif score >= self.RISK_THRESHOLDS["medium"]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _generate_recommendations(
        self, 
        factors: List[RiskFactorResult], 
        risk_level: RiskLevel
    ) -> List[str]:
        """Generate actionable recommendations based on risk factors."""
        recommendations = []
        
        # Sort factors by weighted score (highest first)
        sorted_factors = sorted(factors, key=lambda f: f.weighted_score, reverse=True)
        
        for factor in sorted_factors[:3]:  # Top 3 contributors
            if factor.name == "vulnerabilities" and factor.score > 30:
                recommendations.append("Prioritize patching critical and high CVEs")
            elif factor.name == "exposure" and factor.score > 50:
                recommendations.append("Review network segmentation and reduce attack surface")
            elif factor.name == "criticality" and factor.score >= 75:
                recommendations.append("Ensure enhanced monitoring for this critical asset")
            elif factor.name == "incident_history" and factor.score > 30:
                recommendations.append("Investigate recurring attack patterns on this asset")
            elif factor.name == "threat_intel" and factor.score >= 50:
                recommendations.append("Review IOCs from threat intelligence feeds")
        
        # Add priority-based recommendations
        if risk_level == RiskLevel.CRITICAL:
            recommendations.insert(0, "IMMEDIATE: Escalate to SOC lead and asset owner")
        elif risk_level == RiskLevel.HIGH:
            recommendations.insert(0, "HIGH PRIORITY: Assign to senior analyst within 1 hour")
        
        return recommendations if recommendations else ["Continue standard monitoring"]


# =============================================================================
# Convenience Functions
# =============================================================================

_default_calculator: Optional[AssetRiskCalculator] = None


def get_calculator() -> AssetRiskCalculator:
    """Get or create the default calculator instance."""
    global _default_calculator
    if _default_calculator is None:
        _default_calculator = AssetRiskCalculator()
    return _default_calculator


def calculate_asset_risk(profile: AssetProfile) -> Dict[str, Any]:
    """
    Convenience function to calculate asset risk.
    
    Args:
        profile: Asset profile with all risk factor data.
        
    Returns:
        Risk result as dictionary.
    """
    calculator = get_calculator()
    result = calculator.calculate_risk(profile)
    return result.to_dict()


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Asset Risk Calculator - Test Scenarios")
    print("=" * 70)
    
    calculator = AssetRiskCalculator()
    
    # Scenario 1: Critical production database with vulnerabilities
    print("\n[Scenario 1] Critical Production Database")
    print("-" * 50)
    
    prod_db = AssetProfile(
        asset_id="ASSET-001",
        hostname="prod-db-master-01",
        ip_address="10.0.1.10",
        asset_type=AssetType.DATABASE,
        criticality=Criticality.CRITICAL,
        department="IT",
        function="Domain Controller",
        data_classification=DataClassification.CONFIDENTIAL,
        vulnerabilities=VulnerabilityData(
            critical_count=2,
            high_count=5,
            medium_count=8,
            low_count=3
        ),
        exposure=ExposureData(
            internet_facing=False,
            in_dmz=False,
            internal_only=True,
            open_port_count=5,
            has_privileged_access=True
        ),
        incidents=IncidentData(
            high_incidents=1,
            days_since_last_incident=15
        ),
        threat_intel=ThreatIntelData(
            industry_under_attack=True
        )
    )
    
    result1 = calculator.calculate_risk(prod_db)
    print(f"Risk Score: {result1.risk_score:.1f}/100")
    print(f"Risk Level: {result1.risk_level.value.upper()}")
    print(f"Primary Driver: {result1.primary_driver}")
    print(f"Recommendations: {result1.recommendations[0]}")
    
    # Scenario 2: Test server with same vulnerabilities
    print("\n[Scenario 2] Test Server (Same Vulnerabilities)")
    print("-" * 50)
    
    test_server = AssetProfile(
        asset_id="ASSET-002",
        hostname="test-web-01",
        ip_address="10.0.99.10",
        asset_type=AssetType.SERVER,
        criticality=Criticality.LOW,
        department="QA",
        function="Test Server",
        data_classification=DataClassification.PUBLIC,
        vulnerabilities=VulnerabilityData(
            critical_count=2,
            high_count=5,
            medium_count=8,
            low_count=3
        ),
        exposure=ExposureData(
            internal_only=True,
            isolated=True,
            open_port_count=2
        ),
        incidents=IncidentData(),
        threat_intel=ThreatIntelData()
    )
    
    result2 = calculator.calculate_risk(test_server)
    print(f"Risk Score: {result2.risk_score:.1f}/100")
    print(f"Risk Level: {result2.risk_level.value.upper()}")
    print(f"Primary Driver: {result2.primary_driver}")
    print(f"Recommendations: {result2.recommendations[0]}")
    
    # Scenario 3: Internet-facing web server under active attack
    print("\n[Scenario 3] Internet-Facing Server Under Attack")
    print("-" * 50)
    
    web_server = AssetProfile(
        asset_id="ASSET-003",
        hostname="www-prod-01",
        ip_address="203.0.113.10",
        asset_type=AssetType.SERVER,
        criticality=Criticality.HIGH,
        department="Engineering",
        function="Web Application",
        data_classification=DataClassification.CONFIDENTIAL,
        vulnerabilities=VulnerabilityData(
            critical_count=1,
            high_count=2
        ),
        exposure=ExposureData(
            internet_facing=True,
            open_port_count=3,
            has_privileged_access=True
        ),
        incidents=IncidentData(
            critical_incidents=1,
            days_since_last_incident=3
        ),
        threat_intel=ThreatIntelData(
            in_active_campaign=True
        )
    )
    
    result3 = calculator.calculate_risk(web_server)
    print(f"Risk Score: {result3.risk_score:.1f}/100")
    print(f"Risk Level: {result3.risk_level.value.upper()}")
    print(f"Primary Driver: {result3.primary_driver}")
    print(f"Recommendations: {result3.recommendations[0]}")
    
    # Summary
    print("\n" + "=" * 70)
    print("COMPARISON SUMMARY")
    print("=" * 70)
    print(f"{'Asset':<40} {'Score':<15} {'Level':<15}")
    print("-" * 70)
    print(f"{'Production DB (critical, vulns)':<40} {result1.risk_score:.1f}/100{'':<7} {result1.risk_level.value.upper():<15}")
    print(f"{'Test Server (same vulns, low crit)':<40} {result2.risk_score:.1f}/100{'':<7} {result2.risk_level.value.upper():<15}")
    print(f"{'Web Server (internet, active attack)':<40} {result3.risk_score:.1f}/100{'':<7} {result3.risk_level.value.upper():<15}")
    print("\n[OK] Same vulnerabilities produce different risk based on asset criticality!")
