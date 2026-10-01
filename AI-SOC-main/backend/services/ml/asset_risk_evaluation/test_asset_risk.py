"""
Unit Tests for Asset Risk Evaluation

Tests the core risk calculator, asset profiler, and scoring logic.
"""

import pytest
from datetime import datetime

from .risk_calculator import (
    AssetRiskCalculator,
    AssetProfile,
    AssetType,
    Criticality,
    DataClassification,
    VulnerabilityData,
    ExposureData,
    IncidentData,
    ThreatIntelData,
    RiskLevel,
)
from .asset_profiler import AssetProfiler


class TestAssetRiskCalculator:
    """Tests for the risk calculator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.calculator = AssetRiskCalculator()
    
    def test_weights_sum_to_one(self):
        """Verify weights sum to 100%."""
        total = sum(self.calculator.weights.values())
        assert 0.99 <= total <= 1.01, f"Weights sum to {total}, expected 1.0"
    
    def test_weight_values(self):
        """Verify correct weight values per spec."""
        assert self.calculator.weights["criticality"] == 0.25
        assert self.calculator.weights["vulnerabilities"] == 0.30
        assert self.calculator.weights["exposure"] == 0.20
        assert self.calculator.weights["incident_history"] == 0.15
        assert self.calculator.weights["threat_intel"] == 0.10
    
    def test_critical_asset_high_risk(self):
        """Critical asset with vulnerabilities should be high risk."""
        profile = AssetProfile(
            asset_id="TEST-001",
            hostname="prod-db-01",
            ip_address="10.0.1.10",
            asset_type=AssetType.DATABASE,
            criticality=Criticality.CRITICAL,
            vulnerabilities=VulnerabilityData(critical_count=3, high_count=5),
            exposure=ExposureData(internal_only=True, has_privileged_access=True, open_port_count=5),
            incidents=IncidentData(high_incidents=1, days_since_last_incident=30),
        )
        
        result = self.calculator.calculate_risk(profile)
        
        assert result.risk_score >= 50, f"Critical asset should have high risk score, got {result.risk_score}"
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM]
    
    def test_low_criticality_lower_risk(self):
        """Low criticality asset with same vulns should have lower risk."""
        profile = AssetProfile(
            asset_id="TEST-002",
            hostname="test-server-01",
            ip_address="10.0.99.10",
            asset_type=AssetType.SERVER,
            criticality=Criticality.LOW,
            vulnerabilities=VulnerabilityData(critical_count=2, high_count=3),
            exposure=ExposureData(isolated=True),
        )
        
        result = self.calculator.calculate_risk(profile)
        
        # Should be lower than critical asset
        assert result.risk_score < 70, "Low criticality should reduce overall risk"
    
    def test_vulnerability_scoring(self):
        """Test vulnerability score calculation."""
        # High vulnerability count
        profile = AssetProfile(
            asset_id="TEST-003",
            hostname="test",
            ip_address="10.0.0.1",
            asset_type=AssetType.SERVER,
            criticality=Criticality.MEDIUM,
            vulnerabilities=VulnerabilityData(
                critical_count=4,  # 4 * 25 = 100
                high_count=0,
                medium_count=0,
                low_count=0,
            ),
        )
        
        result = self.calculator.calculate_risk(profile)
        
        # Vulnerability factor should be maxed
        vuln_factor = result.factors["vulnerabilities"]
        assert vuln_factor["raw_score"] == 100
    
    def test_exposure_scoring_internet_facing(self):
        """Internet-facing assets should have high exposure score."""
        profile = AssetProfile(
            asset_id="TEST-004",
            hostname="web-01",
            ip_address="203.0.113.10",
            asset_type=AssetType.SERVER,
            criticality=Criticality.HIGH,
            exposure=ExposureData(
                internet_facing=True,
                open_port_count=5,
                has_privileged_access=True,
            ),
        )
        
        result = self.calculator.calculate_risk(profile)
        
        # Exposure: 40 (internet) + 10 (ports) + 20 (privileged) = 70
        exposure_factor = result.factors["exposure"]
        assert exposure_factor["raw_score"] >= 60
    
    def test_incident_history_decay(self):
        """Recent incidents should contribute more than old ones."""
        # Recent incident
        recent = AssetProfile(
            asset_id="TEST-005",
            hostname="server-a",
            ip_address="10.0.0.1",
            asset_type=AssetType.SERVER,
            criticality=Criticality.MEDIUM,
            incidents=IncidentData(high_incidents=1, days_since_last_incident=5),
        )
        
        # Old incident
        old = AssetProfile(
            asset_id="TEST-006",
            hostname="server-b",
            ip_address="10.0.0.2",
            asset_type=AssetType.SERVER,
            criticality=Criticality.MEDIUM,
            incidents=IncidentData(high_incidents=1, days_since_last_incident=100),
        )
        
        recent_result = self.calculator.calculate_risk(recent)
        old_result = self.calculator.calculate_risk(old)
        
        recent_inc = recent_result.factors["incident_history"]["raw_score"]
        old_inc = old_result.factors["incident_history"]["raw_score"]
        
        assert recent_inc > old_inc, "Recent incidents should score higher"
    
    def test_threat_intel_active_campaign(self):
        """Active campaign should give maximum threat intel score."""
        profile = AssetProfile(
            asset_id="TEST-007",
            hostname="target-01",
            ip_address="10.0.0.1",
            asset_type=AssetType.SERVER,
            criticality=Criticality.HIGH,
            threat_intel=ThreatIntelData(in_active_campaign=True),
        )
        
        result = self.calculator.calculate_risk(profile)
        
        threat_factor = result.factors["threat_intel"]
        assert threat_factor["raw_score"] == 100
    
    def test_risk_level_thresholds(self):
        """Test risk level threshold mappings."""
        # Create profiles at different risk levels
        critical_profile = AssetProfile(
            asset_id="CRIT",
            hostname="prod-critical",
            ip_address="10.0.0.1",
            asset_type=AssetType.DATABASE,
            criticality=Criticality.CRITICAL,
            vulnerabilities=VulnerabilityData(critical_count=4),
            exposure=ExposureData(internet_facing=True, has_privileged_access=True),
            incidents=IncidentData(critical_incidents=1, days_since_last_incident=1),
            threat_intel=ThreatIntelData(in_active_campaign=True),
        )
        
        low_profile = AssetProfile(
            asset_id="LOW",
            hostname="test-sandbox",
            ip_address="10.99.0.1",
            asset_type=AssetType.ENDPOINT,
            criticality=Criticality.LOW,
        )
        
        critical_result = self.calculator.calculate_risk(critical_profile)
        low_result = self.calculator.calculate_risk(low_profile)
        
        assert critical_result.risk_level == RiskLevel.CRITICAL
        assert low_result.risk_level == RiskLevel.LOW
    
    def test_custom_weights(self):
        """Test calculator with custom weights."""
        custom_weights = {
            "criticality": 0.40,  # Increased
            "vulnerabilities": 0.20,
            "exposure": 0.20,
            "incident_history": 0.10,
            "threat_intel": 0.10,
        }
        
        custom_calc = AssetRiskCalculator(weights=custom_weights)
        
        assert custom_calc.weights["criticality"] == 0.40
        assert sum(custom_calc.weights.values()) == 1.0
    
    def test_invalid_weights_rejected(self):
        """Invalid weights should raise error."""
        bad_weights = {
            "criticality": 0.50,
            "vulnerabilities": 0.50,
            # Missing keys
        }
        
        with pytest.raises(ValueError):
            AssetRiskCalculator(weights=bad_weights)


class TestAssetProfiler:
    """Tests for the asset profiler."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.profiler = AssetProfiler()
    
    def test_auto_detect_production(self):
        """Production hostname should detect as critical."""
        profile = self.profiler.create_profile(
            asset_id="TEST-001",
            hostname="prod-db-master-01",
            ip_address="10.0.1.10",
        )
        
        assert profile.criticality == Criticality.CRITICAL
    
    def test_auto_detect_test(self):
        """Test hostname should detect as low."""
        profile = self.profiler.create_profile(
            asset_id="TEST-002",
            hostname="test-web-01",
            ip_address="10.99.0.10",
        )
        
        assert profile.criticality == Criticality.LOW
    
    def test_auto_detect_asset_type(self):
        """Database hostname should detect as database type."""
        profile = self.profiler.create_profile(
            asset_id="TEST-003",
            hostname="mysql-replica-01",
            ip_address="10.0.2.10",
        )
        
        assert profile.asset_type == AssetType.DATABASE
    
    def test_manual_override(self):
        """Manual values should override auto-detection."""
        profile = self.profiler.create_profile(
            asset_id="TEST-004",
            hostname="test-server",  # Would auto-detect as LOW
            ip_address="10.0.0.1",
            criticality=Criticality.CRITICAL,  # Manual override
            asset_type=AssetType.DATABASE,
        )
        
        assert profile.criticality == Criticality.CRITICAL
        assert profile.asset_type == AssetType.DATABASE
    
    def test_get_profile(self):
        """Should retrieve stored profile."""
        self.profiler.create_profile(
            asset_id="TEST-005",
            hostname="server-01",
            ip_address="10.0.0.1",
        )
        
        retrieved = self.profiler.get_profile("TEST-005")
        
        assert retrieved is not None
        assert retrieved.asset_id == "TEST-005"
    
    def test_add_incident(self):
        """Adding incident should update profile."""
        self.profiler.create_profile(
            asset_id="TEST-006",
            hostname="server-02",
            ip_address="10.0.0.2",
        )
        
        updated = self.profiler.add_incident("TEST-006", "high")
        
        assert updated.incidents.high_incidents == 1
        assert updated.incidents.days_since_last_incident == 0


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    # Run with: python -m pytest services/ml/asset_risk_evaluation/test_asset_risk.py -v
    pytest.main([__file__, "-v"])
