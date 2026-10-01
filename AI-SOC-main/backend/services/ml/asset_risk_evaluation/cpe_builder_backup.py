"""
CPE Builder - Constructs Common Platform Enumeration strings from device metadata

CPE 2.3 Format:
cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}

Examples:
- cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*
- cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*
"""

from typing import Dict, List, Optional
import re


class CPEBuilder:
    """Builds CPE 2.3 strings from device and software metadata."""
    
    # OS name to vendor/product mapping
    OS_MAPPINGS = {
        "ubuntu": ("canonical", "ubuntu_linux"),
        "centos": ("centos", "centos"),
        "windows": ("microsoft", "windows"),
        "red hat": ("redhat", "enterprise_linux"),
        "redhat": ("redhat", "enterprise_linux"),
        "debian": ("debian", "debian_linux"),
        "fedora": ("fedora", "fedora"),
        "suse": ("suse", "linux_enterprise"),
        "amazon": ("amazon", "linux"),
        "macos": ("apple", "macos"),
        "mac os": ("apple", "macos"),
    }
    
    # Common application vendor mappings
    APP_VENDORS = {
        "nginx": "nginx",
        "apache": "apache",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "mongodb": "mongodb",
        "redis": "redis",
        "python": "python",
        "java": "oracle",
        "nodejs": "nodejs",
        "node": "nodejs",
        "docker": "docker",
        "kubernetes": "kubernetes",
    }
    
    @classmethod
    def build_os_cpe(cls, os_name: str, os_version: str) -> str:
        """
        Build CPE string for an operating system.
        
        Args:
            os_name: Operating system name (e.g., "Ubuntu", "Windows Server")
            os_version: OS version (e.g., "20.04", "2019")
            
        Returns:
            CPE 2.3 string for the OS
        """
        os_name_lower = os_name.lower()
        
        # Find matching OS mapping
        vendor = product = None
        for key, (v, p) in cls.OS_MAPPINGS.items():
            if key in os_name_lower:
                vendor, product = v, p
                break
        
        # Fallback: use name as both vendor and product
        if not vendor:
            vendor = product = os_name_lower.replace(" ", "_")
        
        # Clean version
        version = cls._clean_version(os_version)
        
        return f"cpe:2.3:o:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    
    @classmethod
    def build_application_cpe(cls, app_name: str, app_version: str, 
                             vendor: Optional[str] = None) -> str:
        """
        Build CPE string for an application/software.
        
        Args:
            app_name: Application name (e.g., "nginx", "OpenSSL")
            app_version: Application version (e.g., "1.18.0")
            vendor: Optional vendor name. If not provided, will try to infer.
            
        Returns:
            CPE 2.3 string for the application
        """
        app_name_lower = app_name.lower()
        
        # Try to find vendor
        if not vendor:
            for key, v in cls.APP_VENDORS.items():
                if key in app_name_lower:
                    vendor = v
                    break
        
        # Fallback: use app name as vendor
        if not vendor:
            vendor = app_name_lower.replace(" ", "_")
        
        product = app_name_lower.replace(" ", "_")
        version = cls._clean_version(app_version)
        
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    
    @classmethod
    def extract_from_ocsf(cls, alert: Dict) -> List[str]:
        """
        Extract and build CPE strings from OCSF alert.
        
        Args:
            alert: OCSF-normalized alert
            
        Returns:
            List of CPE strings found in the alert
        """
        cpes = []
        
        # Extract OS CPE
        device = alert.get("device", {})
        os_info = device.get("os", {})
        
        if os_info.get("name") and os_info.get("version"):
            os_cpe = cls.build_os_cpe(
                os_info["name"],
                os_info["version"]
            )
            cpes.append(os_cpe)
        
        # Extract application CPE from process
        process = alert.get("process", {})
        file_info = process.get("file", {})
        
        if file_info.get("name") and file_info.get("version"):
            app_cpe = cls.build_application_cpe(
                file_info["name"],
                file_info["version"]
            )
            cpes.append(app_cpe)
        
        return cpes
    
    @staticmethod
    def _clean_version(version: str) -> str:
        """Clean and normalize version string."""
        if not version:
            return "*"
        
        # Remove common prefixes
        version = version.lower().replace("version", "").strip()
        version = version.replace("v", "").strip()
        
        # Remove build metadata (everything after '+')
        if "+" in version:
            version = version.split("+")[0]
        
        return version if version else "*"


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("CPE Builder - Test")
    print("=" * 70)
    
    # Test OS CPE
    print("\n[Test 1] OS CPE Building")
    print("-" * 50)
    
    test_os = [
        ("Ubuntu", "20.04"),
        ("Windows Server", "2019"),
        ("Red Hat Enterprise Linux", "8.5"),
        ("Debian", "11"),
    ]
    
    for os_name, os_version in test_os:
        cpe = CPEBuilder.build_os_cpe(os_name, os_version)
        print(f"{os_name} {os_version:8} → {cpe}")
    
    # Test Application CPE
    print("\n[Test 2] Application CPE Building")
    print("-" * 50)
    
    test_apps = [
        ("nginx", "1.18.0"),
        ("Apache HTTP Server", "2.4.46"),
        ("OpenSSL", "1.1.1k"),
        ("MySQL", "8.0.26"),
    ]
    
    for app_name, app_version in test_apps:
        cpe = CPEBuilder.build_application_cpe(app_name, app_version)
        print(f"{app_name:25} {app_version:10} → {cpe}")
    
    # Test OCSF extraction
    print("\n[Test 3] CPE Extraction from OCSF Alert")
    print("-" * 50)
    
    ocsf_alert = {
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
        }
    }
    
    cpes = CPEBuilder.extract_from_ocsf(ocsf_alert)
    print(f"Extracted {len(cpes)} CPEs from alert:")
    for cpe in cpes:
        print(f"  - {cpe}")
    
    print("\n[OK] CPE building working correctly!")
