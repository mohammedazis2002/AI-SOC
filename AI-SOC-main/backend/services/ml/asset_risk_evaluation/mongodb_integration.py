"""
MongoDB Integration Layer for Asset Risk Evaluation

Handles persistent storage for:
- Asset profiles
- Vulnerability cache
- Asset inventory
- Incident history
- Threat intelligence
"""

from typing import Optional, Dict, List
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.collection import Collection
import logging

from .data_models import (
    AssetProfile, VulnerabilityData, IncidentHistoryData,
    ThoroughThreatIntelData
)
from .enums import ComprehensiveAssetType, Industry, Criticality, DataClassification

logger = logging.getLogger(__name__)


class MongoDBIntegration:
    """
    MongoDB persistence layer for asset risk evaluation.
    
    Collections:
    - asset_profiles: Asset metadata and risk scores
    - asset_vulnerabilities: Cached CVE data (7-day expiry)
    - asset_inventory: Installed software + CPE strings
    - incidents: Historical incidents (90-day queries)
    - threat_intelligence: OTX/VT/Abuse data cache
    """
    
    def __init__(self, mongo_uri: str, database_name: str = "soar"):
        """
        Initialize MongoDB connection.
        
        Args:
            mongo_uri: MongoDB connection string
            database_name: Database name (default: soar)
        """
        try:
            self.client = MongoClient(mongo_uri)
            self.db = self.client[database_name]
            
            # Collections
            self.profiles = self.db["asset_profiles"]
            self.vulnerabilities = self.db["asset_vulnerabilities"]
            self.inventory = self.db["asset_inventory"]
            self.incidents = self.db["incidents"]
            self.threat_intel = self.db["threat_intelligence"]
            
            # Create indexes
            self._create_indexes()
            
            logger.info(f"MongoDB connected: {database_name}")
            
        except Exception as e:
            logger.error(f"MongoDB connection failed: {e}")
            raise
    
    def _create_indexes(self):
        """Create necessary indexes for performance."""
        try:
            # Asset profiles
            self.profiles.create_index([("asset_id", ASCENDING)], unique=True)
            self.profiles.create_index([("last_assessed", DESCENDING)])
            
            # Vulnerabilities
            self.vulnerabilities.create_index([("asset_id", ASCENDING)])
            self.vulnerabilities.create_index([("expires_at", ASCENDING)])
            
            # Incidents
            self.incidents.create_index([("asset_id", ASCENDING)])
            self.incidents.create_index([("timestamp", DESCENDING)])
            
            # Threat intelligence
            self.threat_intel.create_index([("indicator", ASCENDING)], unique=True)
            self.threat_intel.create_index([("last_updated", DESCENDING)])
            
            logger.info("MongoDB indexes created")
            
        except Exception as e:
            logger.warning(f"Index creation failed (may already exist): {e}")
    
    # =================================================================
    # Asset Profiles
    # =================================================================
    
    def get_asset_profile(self, asset_id: str) -> Optional[Dict]:
        """Get asset profile from MongoDB."""
        return self.profiles.find_one({"asset_id": asset_id})
    
    def save_asset_profile(self, profile: AssetProfile, risk_score: float, risk_level: str):
        """
        Save or update asset profile with risk score.
        
        Args:
            profile: AssetProfile object
            risk_score: Calculated risk score
            risk_level: Risk level (critical/high/medium/low)
        """
        doc = {
            "asset_id": profile.asset_id,
            "hostname": profile.hostname,
            "ip_address": profile.ip_address,
            "mac_address": profile.mac_address,
            "asset_type": profile.asset_type.value,
            "industry": profile.industry.value,
            "criticality": profile.criticality.value,
            "data_classification": profile.data_classification.value,
            "environment": profile.environment,
            "department": profile.department,
            "owner": profile.owner,
            
            # Compliance flags
            "compliance": {
                "has_pci_data": profile.has_pci_data,
                "has_pii": profile.has_pii,
                "has_phi": profile.has_phi
            },
            
            # OS info
            "os": {
                "name": profile.os_name,
                "version": profile.os_version,
                "edition": profile.os_edition
            },
            
            # Risk score
            "risk_score": risk_score,
            "risk_level": risk_level,
            "last_assessed": datetime.utcnow(),
            
            # Timestamps
            "updated_at": datetime.utcnow()
        }
        
        # Update or insert
        self.profiles.update_one(
            {"asset_id": profile.asset_id},
            {"$set": doc, "$setOnInsert": {"created_at": datetime.utcnow()}},
            upsert=True
        )
        
        logger.info(f"Saved profile for {profile.asset_id} (risk: {risk_score:.2f})")
    
    # =================================================================
    # Vulnerability Cache
    # =================================================================
    
    def get_cached_vulnerabilities(self, asset_id: str) -> Optional[List[Dict]]:
        """
        Get cached vulnerability data (if not expired).
        
        Args:
            asset_id: Asset ID
        
        Returns:
            Vulnerability list or None if expired/not found
        """
        doc = self.vulnerabilities.find_one({
            "asset_id": asset_id,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        if doc:
            logger.info(f"Using cached vulnerabilities for {asset_id}")
            return doc.get("vulnerabilities", [])
        
        return None
    
    def cache_vulnerabilities(
        self,
        asset_id: str,
        vulnerabilities: List[Dict],
        source: str = "nvd",
        cache_days: int = 7
    ):
        """
        Cache vulnerability data.
        
        Args:
            asset_id: Asset ID
            vulnerabilities: List of vulnerability dicts
            source: Data source (nvd, alert, scan)
            cache_days: Cache expiry in days
        """
        # Calculate aggregates
        critical_count = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "high")
        medium_count = sum(1 for v in vulnerabilities if v.get("severity") == "medium")
        low_count = sum(1 for v in vulnerabilities if v.get("severity") == "low")
        
        doc = {
            "asset_id": asset_id,
            "scan_source": source,
            "scan_date": datetime.utcnow(),
            "vulnerabilities": vulnerabilities,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "expires_at": datetime.utcnow() + timedelta(days=cache_days)
        }
        
        self.vulnerabilities.update_one(
            {"asset_id": asset_id},
            {"$set": doc},
            upsert=True
        )
        
        logger.info(f"Cached {len(vulnerabilities)} vulnerabilities for {asset_id}")
    
    # =================================================================
    # Incident History
    # =================================================================
    
    def get_incident_history(self, asset_id: str, days: int = 90) -> IncidentHistoryData:
        """
        Get incident history for asset (last N days).
        
        Args:
            asset_id: Asset ID
            days: Number of days to look back
        
        Returns:
            IncidentHistoryData object
        """
        start_date = datetime.utcnow() - timedelta(days=days)
        
        incidents_cursor = self.incidents.find({
            "asset_id": asset_id,
            "timestamp": {"$gte": start_date}
        }).sort("timestamp", DESCENDING)
        
        incidents_list = list(incidents_cursor)
        
        if not incidents_list:
            return IncidentHistoryData(window_days=days)
        
        # Count by severity
        critical_count = sum(1 for i in incidents_list if i.get("severity") == "critical")
        high_count = sum(1 for i in incidents_list if i.get("severity") == "high")
        medium_count = sum(1 for i in incidents_list if i.get("severity") == "medium")
        low_count = sum(1 for i in incidents_list if i.get("severity") == "low")
        
        # Most recent
        most_recent = incidents_list[0]
        
        # Check for recidivism
        is_repeat = len(incidents_list) >= 3  # 3+ incidents in 90 days
        
        return IncidentHistoryData(
            critical_incidents=critical_count,
            high_incidents=high_count,
            medium_incidents=medium_count,
            low_incidents=low_count,
            most_recent_incident_date=most_recent.get("timestamp"),
            most_recent_severity=most_recent.get("severity"),
            window_days=days,
            is_repeat_offender=is_repeat
        )
    
    def save_incident(self, incident_data: Dict):
        """Save incident to database."""
        self.incidents.insert_one(incident_data)
        logger.info(f"Saved incident for {incident_data.get('asset_id')}")
    
    # =================================================================
    # Threat Intelligence Cache
    # =================================================================
    
    def get_threat_intel(self, indicator: str, indicator_type: str = "ip") -> Optional[Dict]:
        """
        Get cached threat intelligence.
        
        Args:
            indicator: IP address or other IOC
            indicator_type: Type (ip, domain, hash)
        
        Returns:
            Threat intel dict or None
        """
        return self.threat_intel.find_one({
            "indicator": indicator,
            "indicator_type": indicator_type
        })
    
    def cache_threat_intel(self, indicator: str, indicator_type: str, data: Dict):
        """
        Cache threat intelligence data.
        
        Args:
            indicator: IP address or other IOC
            indicator_type: Type (ip, domain, hash)
            data: Threat intel data from APIs
        """
        doc = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "last_updated": datetime.utcnow(),
            **data
        }
        
        self.threat_intel.update_one(
            {"indicator": indicator, "indicator_type": indicator_type},
            {"$set": doc},
            upsert=True
        )
    
    # =================================================================
    # Asset Inventory
    # =================================================================
    
    def get_asset_inventory(self, asset_id: str) -> Optional[Dict]:
        """Get asset inventory (installed software)."""
        return self.inventory.find_one({"asset_id": asset_id})
    
    def save_asset_inventory(self, asset_id: str, inventory_data: Dict):
        """Save asset inventory."""
        doc = {
            "asset_id": inventory_data.get("hostname", asset_id),
            **inventory_data,
            "last_updated": datetime.utcnow()
        }
        
        self.inventory.update_one(
            {"asset_id": asset_id},
            {"$set": doc},
            upsert=True
        )
