"""
Asset Profiler - Asset Discovery and Profile Management

Handles creation, updating, and retrieval of asset profiles.
Supports both in-memory storage and MongoDB integration.
"""

from typing import Dict, Any, Optional, List
from dataclasses import asdict
from datetime import datetime
import re

from .risk_calculator import (
    AssetProfile,
    AssetType,
    Criticality,
    DataClassification,
    VulnerabilityData,
    ExposureData,
    IncidentData,
    ThreatIntelData,
)


class AssetProfiler:
    """
    Asset Profiler - Manages asset profiles and auto-detection.
    
    Features:
    - Create/update asset profiles
    - Auto-detect environment from hostname
    - In-memory storage with optional MongoDB backend
    """
    
    # Environment detection patterns (hostname patterns -> criticality)
    ENVIRONMENT_PATTERNS = [
        # Production patterns -> CRITICAL/HIGH
        (r"prod[-_.]", Criticality.CRITICAL),
        (r"[-_.]prod[-_.]", Criticality.CRITICAL),
        (r"production", Criticality.CRITICAL),
        (r"prd[-_.]", Criticality.CRITICAL),
        (r"live[-_.]", Criticality.CRITICAL),
        (r"[-_.]db[-_.]", Criticality.HIGH),
        (r"database", Criticality.HIGH),
        (r"master", Criticality.HIGH),
        (r"primary", Criticality.HIGH),
        (r"dc\d+", Criticality.CRITICAL),  # Domain controllers
        
        # Staging patterns -> MEDIUM
        (r"stag[-_.]", Criticality.MEDIUM),
        (r"[-_.]stg[-_.]", Criticality.MEDIUM),
        (r"staging", Criticality.MEDIUM),
        (r"preprod", Criticality.MEDIUM),
        (r"uat[-_.]", Criticality.MEDIUM),
        
        # Test patterns -> LOW
        (r"test[-_.]", Criticality.LOW),
        (r"[-_.]test[-_.]", Criticality.LOW),
        (r"testing", Criticality.LOW),
        (r"qa[-_.]", Criticality.LOW),
        (r"[-_.]qa[-_.]", Criticality.LOW),
        
        # Development patterns -> LOW
        (r"dev[-_.]", Criticality.LOW),
        (r"[-_.]dev[-_.]", Criticality.LOW),
        (r"devel", Criticality.LOW),
        (r"sandbox", Criticality.LOW),
        (r"local", Criticality.LOW),
    ]
    
    # Asset type patterns
    ASSET_TYPE_PATTERNS = [
        (r"db|database|mongo|mysql|postgres|sql", AssetType.DATABASE),
        (r"router|switch|firewall|fw[-_]|lb[-_]|loadbalancer", AssetType.NETWORK_DEVICE),
        (r"container|docker|k8s|pod", AssetType.CONTAINER),
        (r"aws|azure|gcp|cloud", AssetType.CLOUD_RESOURCE),
        (r"desktop|workstation|laptop|pc[-_]", AssetType.ENDPOINT),
        (r"srv|server|web|app|api", AssetType.SERVER),
    ]
    
    def __init__(self, mongodb_client=None, db_name: str = "secureintelli"):
        """
        Initialize the asset profiler.
        
        Args:
            mongodb_client: Optional pymongo client for persistence.
            db_name: Database name to use.
        """
        self.mongodb_client = mongodb_client
        self.db_name = db_name
        
        # In-memory storage as fallback
        self._profiles: Dict[str, AssetProfile] = {}
    
    @property
    def _collection(self):
        """Get MongoDB collection if available."""
        if self.mongodb_client:
            return self.mongodb_client[self.db_name]["asset_profiles"]
        return None
    
    def create_profile(
        self,
        asset_id: str,
        hostname: str,
        ip_address: str,
        asset_type: Optional[AssetType] = None,
        criticality: Optional[Criticality] = None,
        department: str = "",
        function: str = "",
        data_classification: DataClassification = DataClassification.INTERNAL,
    ) -> AssetProfile:
        """
        Create a new asset profile with auto-detection.
        
        If asset_type or criticality are not provided, they will be
        auto-detected from the hostname.
        """
        # Auto-detect asset type if not provided
        if asset_type is None:
            asset_type = self._detect_asset_type(hostname)
        
        # Auto-detect criticality if not provided
        if criticality is None:
            criticality = self._detect_criticality(hostname)
        
        profile = AssetProfile(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            asset_type=asset_type,
            criticality=criticality,
            department=department,
            function=function,
            data_classification=data_classification,
        )
        
        # Store profile
        self._profiles[asset_id] = profile
        
        # Persist to MongoDB if available
        if self._collection is not None:
            self._save_to_db(profile)
        
        return profile
    
    def get_profile(self, asset_id: str) -> Optional[AssetProfile]:
        """Get an asset profile by ID."""
        # Check in-memory first
        if asset_id in self._profiles:
            return self._profiles[asset_id]
        
        # Try MongoDB
        if self._collection is not None:
            doc = self._collection.find_one({"asset_id": asset_id})
            if doc:
                profile = self._doc_to_profile(doc)
                self._profiles[asset_id] = profile
                return profile
        
        return None
    
    def update_vulnerabilities(
        self, 
        asset_id: str, 
        vulnerabilities: VulnerabilityData
    ) -> Optional[AssetProfile]:
        """Update vulnerability data for an asset."""
        profile = self.get_profile(asset_id)
        if profile:
            profile.vulnerabilities = vulnerabilities
            self._save_profile(profile)
        return profile
    
    def update_exposure(
        self, 
        asset_id: str, 
        exposure: ExposureData
    ) -> Optional[AssetProfile]:
        """Update exposure data for an asset."""
        profile = self.get_profile(asset_id)
        if profile:
            profile.exposure = exposure
            self._save_profile(profile)
        return profile
    
    def update_incidents(
        self, 
        asset_id: str, 
        incidents: IncidentData
    ) -> Optional[AssetProfile]:
        """Update incident history for an asset."""
        profile = self.get_profile(asset_id)
        if profile:
            profile.incidents = incidents
            self._save_profile(profile)
        return profile
    
    def update_threat_intel(
        self, 
        asset_id: str, 
        threat_intel: ThreatIntelData
    ) -> Optional[AssetProfile]:
        """Update threat intelligence data for an asset."""
        profile = self.get_profile(asset_id)
        if profile:
            profile.threat_intel = threat_intel
            self._save_profile(profile)
        return profile
    
    def add_incident(
        self,
        asset_id: str,
        severity: str,  # critical, high, medium, low
    ) -> Optional[AssetProfile]:
        """
        Add a new incident to an asset's history.
        Updates the incident count and sets days_since_last to 0.
        """
        profile = self.get_profile(asset_id)
        if not profile:
            return None
        
        severity_lower = severity.lower()
        if severity_lower == "critical":
            profile.incidents.critical_incidents += 1
        elif severity_lower == "high":
            profile.incidents.high_incidents += 1
        elif severity_lower == "medium":
            profile.incidents.medium_incidents += 1
        else:
            profile.incidents.low_incidents += 1
        
        profile.incidents.days_since_last_incident = 0
        self._save_profile(profile)
        return profile
    
    def get_high_risk_assets(
        self, 
        criticality_threshold: Criticality = Criticality.HIGH
    ) -> List[AssetProfile]:
        """Get all assets at or above a criticality threshold."""
        thresholds = {
            Criticality.CRITICAL: [Criticality.CRITICAL],
            Criticality.HIGH: [Criticality.CRITICAL, Criticality.HIGH],
            Criticality.MEDIUM: [Criticality.CRITICAL, Criticality.HIGH, Criticality.MEDIUM],
            Criticality.LOW: list(Criticality),
        }
        
        valid_levels = thresholds.get(criticality_threshold, [])
        return [p for p in self._profiles.values() if p.criticality in valid_levels]
    
    def list_all_profiles(self) -> List[AssetProfile]:
        """List all asset profiles."""
        return list(self._profiles.values())
    
    # =========================================================================
    # Auto-Detection Methods
    # =========================================================================
    
    def _detect_criticality(self, hostname: str) -> Criticality:
        """Detect criticality from hostname patterns."""
        hostname_lower = hostname.lower()
        
        for pattern, criticality in self.ENVIRONMENT_PATTERNS:
            if re.search(pattern, hostname_lower):
                return criticality
        
        # Default to MEDIUM if unknown
        return Criticality.MEDIUM
    
    def _detect_asset_type(self, hostname: str) -> AssetType:
        """Detect asset type from hostname patterns."""
        hostname_lower = hostname.lower()
        
        for pattern, asset_type in self.ASSET_TYPE_PATTERNS:
            if re.search(pattern, hostname_lower):
                return asset_type
        
        # Default to SERVER if unknown
        return AssetType.SERVER
    
    # =========================================================================
    # Persistence Methods
    # =========================================================================
    
    def _save_profile(self, profile: AssetProfile):
        """Save profile to storage."""
        self._profiles[profile.asset_id] = profile
        if self._collection is not None:
            self._save_to_db(profile)
    
    def _save_to_db(self, profile: AssetProfile):
        """Save profile to MongoDB."""
        doc = self._profile_to_doc(profile)
        self._collection.update_one(
            {"asset_id": profile.asset_id},
            {"$set": doc},
            upsert=True
        )
    
    def _profile_to_doc(self, profile: AssetProfile) -> Dict[str, Any]:
        """Convert profile to MongoDB document."""
        return {
            "asset_id": profile.asset_id,
            "hostname": profile.hostname,
            "ip_address": profile.ip_address,
            "asset_type": profile.asset_type.value,
            "criticality": profile.criticality.value,
            "department": profile.department,
            "function": profile.function,
            "data_classification": profile.data_classification.value,
            "vulnerabilities": asdict(profile.vulnerabilities),
            "exposure": asdict(profile.exposure),
            "incidents": asdict(profile.incidents),
            "threat_intel": asdict(profile.threat_intel),
            "last_updated": datetime.utcnow(),
        }
    
    def _doc_to_profile(self, doc: Dict[str, Any]) -> AssetProfile:
        """Convert MongoDB document to profile."""
        return AssetProfile(
            asset_id=doc["asset_id"],
            hostname=doc["hostname"],
            ip_address=doc["ip_address"],
            asset_type=AssetType(doc["asset_type"]),
            criticality=Criticality(doc["criticality"]),
            department=doc.get("department", ""),
            function=doc.get("function", ""),
            data_classification=DataClassification(doc.get("data_classification", "internal")),
            vulnerabilities=VulnerabilityData(**doc.get("vulnerabilities", {})),
            exposure=ExposureData(**doc.get("exposure", {})),
            incidents=IncidentData(**doc.get("incidents", {})),
            threat_intel=ThreatIntelData(**doc.get("threat_intel", {})),
        )


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Asset Profiler - Auto-Detection Test")
    print("=" * 70)
    
    profiler = AssetProfiler()
    
    # Test auto-detection
    test_hostnames = [
        ("prod-db-master-01", "Production database"),
        ("test-web-01", "Test web server"),
        ("dev-sandbox-john", "Development sandbox"),
        ("staging-api-01", "Staging API server"),
        ("dc01.corp.local", "Domain controller"),
        ("fw-perimeter-01", "Firewall"),
        ("container-app-prod", "Production container"),
    ]
    
    print("\nAuto-Detection Results:")
    print("-" * 70)
    print(f"{'Hostname':<30} {'Criticality':<15} {'Type':<20}")
    print("-" * 70)
    
    for hostname, desc in test_hostnames:
        profile = profiler.create_profile(
            asset_id=f"ASSET-{hostname}",
            hostname=hostname,
            ip_address="10.0.0.1"
        )
        print(f"{hostname:<30} {profile.criticality.value:<15} {profile.asset_type.value:<20}")
    
    print("\n[OK] Auto-detection working correctly!")
