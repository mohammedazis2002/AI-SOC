"""
OCSF to Asset Risk Extractor - Integration Layer

Extracts asset data from OCSF alerts and discovers vulnerabilities
using NVD API when vulnerability data is not in the alert.

This is the KEY INTEGRATION that was missing from the external implementation.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

from .asset_inventory import AssetInventoryManager
from .risk_calculator import (
    AssetProfile, AssetType, Criticality, DataClassification,
    VulnerabilityData, ExposureData, IncidentData, ThreatIntelData,
    AssetRiskCalculator
)

logger = logging.getLogger(__name__)


class OCSFAssetExtractor:
    """
    Extracts asset profiles from OCSF alerts and discovers vulnerabilities.
    
    Features:
    - Extract asset data from OCSF alerts
    - Build or update asset inventory  
    - Query NVD for vulnerabilities if not in alert
    - Generate complete AssetProfile for risk calculation
    """
    
    def __init__(self, mongodb_client=None):
        """
        Initialize the extractor.
        
        Args:
            mongodb_client: MongoDB client for persistence
        """
        self.inventory_manager = AssetInventoryManager(mongodb_client)
        self.risk_calculator = AssetRiskCalculator()
    
    def extract_and_assess_risk(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Complete workflow: Extract asset from alert → Discover vulnerabilities → Calculate risk.
        
        This is called by the alert processing pipeline.
        
        Args:
            alert: OCSF-normalized alert
            
        Returns:
            Risk assessment dict or None if insufficient data
        """
        # Step 1: Extract basic asset info from alert
        device = alert.get("device", {})
        asset_id = device.get("hostname") or device.get("ip")
        
        if not asset_id:
            logger.warning("No asset identifier in alert")
            return None
        
        # Step 2: Update asset inventory from alert
        inventory = self.inventory_manager.update_from_ocsf_alert(alert)
        
        # Step 3: Check if alert contains vulnerability data
        has_vuln_data = alert.get("class_name") == "Vulnerability Finding"
        
        # Step 4: Discover vulnerabilities if not in alert
        vulnerabilities = []
        if has_vuln_data:
            # Use vulnerability data from alert
            vulnerabilities = alert.get("vulnerabilities", [])
            logger.info(f"Using {len(vulnerabilities)} vulnerabilities from alert")
        else:
            # KEY FEATURE: Query NVD for vulnerabilities
            logger.info(f"No vulnerability data in alert, querying NVD for {asset_id}")
            vulnerabilities = self.inventory_manager.discover_vulnerabilities_for_asset(asset_id)
        
        # Step 5: Build AssetProfile for risk calculation
        profile = self._build_asset_profile(alert, asset_id, vulnerabilities)
        
        if not profile:
            logger.warning(f"Could not build profile for {asset_id}")
            return None
        
        # Step 6: Calculate risk
        risk_result = self.risk_calculator.calculate_risk(profile)
        
        return risk_result.to_dict()
    
    def _build_asset_profile(
        self,
        alert: Dict[str, Any],
        asset_id: str,
        vulnerabilities: List[Dict]
    ) -> Optional[AssetProfile]:
        """
        Build complete AssetProfile from alert and discovered vulnerabilities.
        
        Args:
            alert: OCSF alert
            asset_id: Asset identifier
            vulnerabilities: List of vulnerabilities (from alert or NVD)
            
        Returns:
            AssetProfile ready for risk calculation
        """
        device = alert.get("device", {})
        os_info = device.get("os", {})
        
        # Determine criticality (can be enhanced with business context)
        criticality = self._infer_criticality(device.get("hostname", ""))
        
        # Determine asset type
        asset_type = self._infer_asset_type(device.get("hostname", ""), os_info.get("name", ""))
        
        # Build vulnerability data
        vuln_data = self._aggregate_vulnerabilities(vulnerabilities)
        
        # Build exposure data from alert metadata
        exposure_data = self._extract_exposure(alert)
        
        # Build incident data (placeholder - would query incident DB)
        incident_data = IncidentData()  # TODO: Query incident history
        
        # Build threat intel data (placeholder - would query threat correlator)
        threat_data = ThreatIntelData()  # TODO: Query threat intelligence
        
        try:
            profile = AssetProfile(
                asset_id=asset_id,
                hostname=device.get("hostname", ""),
                ip_address=device.get("ip", ""),
                asset_type=asset_type,
                criticality=criticality,
                department="",  # TODO: Map from asset inventory
                function="",    # TODO: Map from asset inventory
                data_classification=DataClassification.INTERNAL,
                vulnerabilities=vuln_data,
                exposure=exposure_data,
                incidents=incident_data,
                threat_intel=threat_data
            )
            return profile
        except Exception as e:
            logger.error(f"Failed to build asset profile: {e}")
            return None
    
    def _aggregate_vulnerabilities(self, vulnerabilities: List[Dict]) -> VulnerabilityData:
        """
        Aggregate vulnerability list into VulnerabilityData.
        
        Args:
            vulnerabilities: List of CVEs with severity
            
        Returns:
            VulnerabilityData with counts
        """
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        oldest_date = datetime.utcnow()
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in counts:
                counts[severity] += 1
            
            # Track oldest
            published = vuln.get("published_date") or vuln.get("discovered_date")
            if published:
                if isinstance(published, str):
                    try:
                        published = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    except:
                        pass
                if isinstance(published, datetime) and published < oldest_date:
                    oldest_date = published
        
        oldest_days = (datetime.utcnow() - oldest_date).days if vulnerabilities else 0
        
        return VulnerabilityData(
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            oldest_unpatched_days=oldest_days
        )
    
    def _extract_exposure(self, alert: Dict[str, Any]) -> ExposureData:
        """Extract network exposure data from alert."""
        metadata = alert.get("metadata", {})
        
        return ExposureData(
            internet_facing=metadata.get("internet_facing", False),
            in_dmz=metadata.get("dmz", False),
            internal_only=not metadata.get("internet_facing", False),
            isolated=False,  # TODO: Detect from network info
            open_port_count=0,  # TODO: Extract from alert if available
            has_privileged_access=False  # TODO: Detect from user/process info
        )
    
    def _infer_criticality(self, hostname: str) -> Criticality:
        """Infer asset criticality from hostname patterns."""
        hostname_lower = hostname.lower()
        
        # Critical patterns
        if any(pattern in hostname_lower for pattern in 
               ["dc", "domain", "prod-db", "payment", "auth"]):
            return Criticality.CRITICAL
        
        # High patterns
        if any(pattern in hostname_lower for pattern in 
               ["prod", "app", "web", "api", "file"]):
            return Criticality.HIGH
        
        # Low patterns
        if any(pattern in hostname_lower for pattern in 
               ["test", "dev", "staging", "qa", "guest"]):
            return Criticality.LOW
        
        # Default to medium
        return Criticality.MEDIUM
    
    def _infer_asset_type(self, hostname: str, os_name: str) -> AssetType:
        """Infer asset type from hostname and OS."""
        hostname_lower = hostname.lower()
        os_lower = os_name.lower()
        
        # Database servers
        if any(pattern in hostname_lower for pattern in ["db", "database", "sql", "mongo"]):
            return AssetType.DATABASE
        
        # Network devices
        if any(pattern in hostname_lower for pattern in ["fw", "firewall", "router", "switch"]):
            return AssetType.NETWORK_DEVICE
        
        # Servers
        if any(pattern in hostname_lower for pattern in ["srv", "server", "prod", "app", "web"]):
            return AssetType.SERVER
        
        # Cloud resources
        if "cloud" in hostname_lower or any(pattern in os_lower for pattern in ["aws", "azure", "gcp"]):
            return AssetType.CLOUD_RESOURCE
        
        # Default to endpoint
        return AssetType.ENDPOINT


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("OCSF Asset Extractor - Test")
    print("=" * 70)
    
    extractor = OCSFAssetExtractor()
    
    # Test: OCSF alert WITHOUT vulnerability data
    print("\n[Test 1] Alert WITHOUT vulnerability data → Query NVD")
    print("-" * 50)
    
    alert_without_vulns = {
        "class_name": "Network Activity",
        "device": {
            "hostname": "web-server-01",
            "ip": "10.0.1.50",
            "os": {
                "name": "Ubuntu",
                "version": "20.04"
            }
        },
        "process": {
            "file": {
                "name": "nginx",
                "version": "1.18.0"
            }
        },
        "severity": "medium",
        "metadata": {
            "internet_facing": True
        }
    }
    
    print("Processing alert...")
    print("This will query NVD API (may take 30+ seconds)...")
    
    risk_result = extractor.extract_and_assess_risk(alert_without_vulns)
    
    if risk_result:
        print(f"\n✅ Risk Assessment:")
        print(f"  Asset: {risk_result['asset_id']}")
        print(f"  Risk Score: {risk_result['risk_score']}/100")
        print(f"  Risk Level: {risk_result['risk_level'].upper()}")
        print(f"  Primary Driver: {risk_result['primary_driver']}")
        
        print(f"\n  Vulnerability Factor:")
        vuln_factor = risk_result['factors']['vulnerabilities']
        print(f"    Raw Score: {vuln_factor['raw_score']}")
        print(f"    Reason: {vuln_factor['reason']}")
    else:
        print("❌ Risk assessment failed")
    
    # Test: OCSF alert WITH vulnerability data
    print("\n[Test 2] Alert WITH vulnerability data → Use directly")
    print("-" * 50)
    
    alert_with_vulns = {
        "class_name": "Vulnerability Finding",
        "device": {
            "hostname": "prod-db-01",
            "ip": "10.0.1.10",
            "os": {
                "name": "Red Hat Enterprise Linux",
                "version": "8.5"
            }
        },
        "vulnerabilities": [
            {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "severity": "critical"},
            {"cve_id": "CVE-2024-5678", "cvss_score": 7.5, "severity": "high"},
            {"cve_id": "CVE-2024-9999", "cvss_score": 4.3, "severity": "medium"},
        ],
        "severity": "critical",
        "metadata": {
            "internet_facing": False,
            "dmz": False
        }
    }
    
    print("Processing alert with vulnerability data...")
    
    risk_result2 = extractor.extract_and_assess_risk(alert_with_vulns)
    
    if risk_result2:
        print(f"\n✅ Risk Assessment:")
        print(f"  Asset: {risk_result2['asset_id']}")
        print(f"  Risk Score: {risk_result2['risk_score']}/100")
        print(f"  Risk Level: {risk_result2['risk_level'].upper()}")
        print(f"  Primary Driver: {risk_result2['primary_driver']}")
        
        print(f"\n  Vulnerability Factor:")
        vuln_factor = risk_result2['factors']['vulnerabilities']
        print(f"    Raw Score: {vuln_factor['raw_score']}")
        print(f"    Reason: {vuln_factor['reason']}")
    else:
        print("❌ Risk assessment failed")
    
    print("\n[OK] OCSF extraction and risk assessment working!")
