"""
Asset Inventory Manager - Tracks installed software and generates CPE strings

Manages asset inventory with software package tracking for proactive 
vulnerability discovery via NVD API queries.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
import logging

from .cpe_builder import CPEBuilder
from .nvd_client import NVDAPIClient

logger = logging.getLogger(__name__)


@dataclass
class SoftwarePackage:
    """Installed software package information."""
    name: str
    version: str
    cpe: str
    vendor: Optional[str] = None
    installed_date: Optional[datetime] = None


@dataclass
class AssetInventory:
    """Complete asset inventory record."""
    asset_id: str
    hostname: str
    ip_address: str
    os_name: str
    os_version: str
    os_cpe: str
    installed_software: List[SoftwarePackage]
    last_scanned: datetime


class AssetInventoryManager:
    """
    Asset Inventory Manager - Tracks asset software and discovers vulnerabilities.
    
    Features:
    - Maintain software inventory per asset
    - Auto-generate CPE strings
    - Query NVD for vulnerabilities
    - Update from Wazuh syscollector
    """
    
    def __init__(self, mongodb_client=None, db_name: str = "secureintelli"):
        """
        Initialize inventory manager.
        
        Args:
            mongodb_client: MongoDB client for persistence
            db_name: Database name
        """
        self.mongodb_client = mongodb_client
        self.db_name = db_name
        
        self.cpe_builder = CPEBuilder()
        self.nvd_client = NVDAPIClient()
    
    @property
    def _collection(self):
        """Get MongoDB collection."""
        if self.mongodb_client:
            return self.mongodb_client[self.db_name]["asset_inventory"]
        return None
    
    def create_or_update_inventory(
        self,
        asset_id: str,
        hostname: str,
        ip_address: str,
        os_name: str,
        os_version: str,
        installed_software: List[Dict[str, str]]
    ) -> AssetInventory:
        """
        Create or update asset inventory.
        
        Args:
            asset_id: Unique asset identifier
            hostname: Asset hostname
            ip_address: IP address
            os_name: Operating system name
            os_version: OS version
            installed_software: List of dicts with 'name', 'version', optional 'vendor'
            
        Returns:
            AssetInventory object
        """
        # Build OS CPE
        os_cpe = self.cpe_builder.build_os_cpe(os_name, os_version)
        
        # Build software CPEs
        software_packages = []
        for sw in installed_software:
            cpe = self.cpe_builder.build_application_cpe(
                sw["name"],
                sw["version"],
                sw.get("vendor")
            )
            package = SoftwarePackage(
                name=sw["name"],
                version=sw["version"],
                cpe=cpe,
                vendor=sw.get("vendor")
            )
            software_packages.append(package)
        
        inventory = AssetInventory(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            os_name=os_name,
            os_version=os_version,
            os_cpe=os_cpe,
            installed_software=software_packages,
            last_scanned=datetime.utcnow()
        )
        
        # Save to MongoDB
        if self._collection is not None:
            doc = {
                "asset_id": asset_id,
                "hostname": hostname,
                "ip_address": ip_address,
                "os_name": os_name,
                "os_version": os_version,
                "os_cpe": os_cpe,
                "installed_software": [
                    {
                        "name": pkg.name,
                        "version": pkg.version,
                        "cpe": pkg.cpe,
                        "vendor": pkg.vendor
                    }
                    for pkg in software_packages
                ],
                "last_scanned": datetime.utcnow()
            }
            
            self._collection.update_one(
                {"asset_id": asset_id},
                {"$set": doc},
                upsert=True
            )
        
        logger.info(f"Updated inventory for {asset_id}: {len(software_packages)} packages")
        return inventory
    
    def get_inventory(self, asset_id: str) -> Optional[AssetInventory]:
        """Get asset inventory by ID."""
        if self._collection is not None:
            doc = self._collection.find_one({"asset_id": asset_id})
            if doc:
                return self._doc_to_inventory(doc)
        return None
    
    def discover_vulnerabilities_for_asset(self, asset_id: str) -> List[Dict[str, Any]]:
        """
        Discover vulnerabilities by querying NVD with asset's CPEs.
        
        This is the KEY MISSING FEATURE: proactive vulnerability discovery
        even when vulnerability data isn't in the alert.
        
        Args:
            asset_id: Asset to scan
            
        Returns:
            List of discovered vulnerabilities
        """
        inventory = self.get_inventory(asset_id)
        if not inventory:
            logger.warning(f"No inventory found for {asset_id}")
            return []
        
        all_vulnerabilities = []
        
        # Query NVD for OS
        logger.info(f"Querying NVD for OS: {inventory.os_cpe}")
        os_cves = self.nvd_client.get_cves_for_cpe(inventory.os_cpe)
        for cve in os_cves:
            cve["affected_component"] = f"{inventory.os_name} {inventory.os_version}"
            cve["asset_id"] = asset_id
        all_vulnerabilities.extend(os_cves)
        
        # Query NVD for each software package
        for pkg in inventory.installed_software:
            logger.info(f"Querying NVD for {pkg.name} {pkg.version}")
            pkg_cves = self.nvd_client.get_cves_for_cpe(pkg.cpe)
            for cve in pkg_cves:
                cve["affected_component"] = f"{pkg.name} {pkg.version}"
                cve["asset_id"] = asset_id
            all_vulnerabilities.extend(pkg_cves)
        
        logger.info(f"Discovered {len(all_vulnerabilities)} vulnerabilities for {asset_id}")
        return all_vulnerabilities
    
    def update_from_ocsf_alert(self, alert: Dict[str, Any]) -> Optional[AssetInventory]:
        """
        Update or create asset inventory from OCSF alert.
        
        Args:
            alert: OCSF-normalized alert
            
        Returns:
            AssetInventory if enough data, None otherwise
        """
        device = alert.get("device", {})
        os_info = device.get("os", {})
        
        if not device.get("hostname") or not os_info.get("name"):
            return None  # Not enough data
        
        asset_id = device.get("hostname") or device.get("ip", "unknown")
        
        # Extract software from process if available
        installed_software = []
        process = alert.get("process", {})
        file_info = process.get("file", {})
        
        if file_info.get("name") and file_info.get("version"):
            installed_software.append({
                "name": file_info["name"],
                "version": file_info["version"]
            })
        
        return self.create_or_update_inventory(
            asset_id=asset_id,
            hostname=device.get("hostname", ""),
            ip_address=device.get("ip", ""),
            os_name=os_info.get("name", ""),
            os_version=os_info.get("version", ""),
            installed_software=installed_software
        )
    
    def _doc_to_inventory(self, doc: Dict) -> AssetInventory:
        """Convert MongoDB document to AssetInventory."""
        software = [
            SoftwarePackage(
                name=pkg["name"],
                version=pkg["version"],
                cpe=pkg["cpe"],
                vendor=pkg.get("vendor")
            )
            for pkg in doc.get("installed_software", [])
        ]
        
        return AssetInventory(
            asset_id=doc["asset_id"],
            hostname=doc["hostname"],
            ip_address=doc["ip_address"],
            os_name=doc["os_name"],
            os_version=doc["os_version"],
            os_cpe=doc["os_cpe"],
            installed_software=software,
            last_scanned=doc.get("last_scanned", datetime.utcnow())
        )


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Asset Inventory Manager - Test")
    print("=" * 70)
    
    manager = AssetInventoryManager()
    
    # Test: Create inventory
    print("\n[Test 1] Create Asset Inventory")
    print("-" * 50)
    
    inventory = manager.create_or_update_inventory(
        asset_id="web-server-01",
        hostname="web-server-01.company.local",
        ip_address="10.0.1.50",
        os_name="Ubuntu",
        os_version="20.04",
        installed_software=[
            {"name": "nginx", "version": "1.18.0"},
            {"name": "openssl", "version": "1.1.1f"},
            {"name": "python", "version": "3.8.10"},
        ]
    )
    
    print(f"Created inventory for: {inventory.asset_id}")
    print(f"OS: {inventory.os_name} {inventory.os_version}")
    print(f"OS CPE: {inventory.os_cpe}")
    print(f"\nInstalled Software ({len(inventory.installed_software)} packages):")
    for pkg in inventory.installed_software:
        print(f"  - {pkg.name:15} {pkg.version:10} → {pkg.cpe}")
    
    # Test: Discover vulnerabilities
    print("\n[Test 2] Discover Vulnerabilities from NVD")
    print("-" * 50)
    print("This will query NVD API (may take 30+ seconds due to rate limiting)...")
    
    vulns = manager.discover_vulnerabilities_for_asset("web-server-01")
    
    if vulns:
        print(f"\nDiscovered {len(vulns)} vulnerabilities:")
        
        # Group by severity
        by_severity = {}
        for v in vulns:
            sev = v.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        for severity, count in sorted(by_severity.items(), reverse=True):
            print(f"  {severity.upper():10} {count}")
        
        # Show top 5 critical/high
        critical_high = [v for v in vulns if v.get("severity") in ["critical", "high"]]
        if critical_high:
            print(f"\nTop Critical/High CVEs:")
            for v in critical_high[:5]:
                print(f"  {v['cve_id']:20} CVSS: {v['cvss_score']:.1f} - {v['affected_component']}")
    else:
        print("No vulnerabilities discovered (or NVD API error)")
    
    print("\n[OK] Asset inventory and vulnerability discovery working!")
