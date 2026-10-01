"""
NVD API Client - Queries NIST National Vulnerability Database

Retrieves CVE and CVSS data for CPE strings.
API Documentation: https://nvd.nist.gov/developers/vulnerabilities

Rate Limits:
- No API key: 5 requests per 30 seconds  
- With API key: 50 requests per 30 seconds

Set NVD_API_KEY environment variable to use authenticated requests.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import time
import os
import logging

# Try to import requests
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


class NVDAPIClient:
    """
    NIST NVD API Client for CVE/CVSS data retrieval.
    
    Features:
    - Query CVEs by CPE
    - Automatic rate limiting
    - Response caching
    - API key support
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD API client.
        
        Args:
            api_key: Optional NVD API key for higher rate limits.
                    If not provided, reads from NVD_API_KEY env var.
        """
        if not HAS_REQUESTS:
            raise ImportError("requests library required. Install with: pip install requests")
        
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.last_request_time = None
        self._cache: Dict[str, Dict] = {}
        
        # Rate limiting
        if self.api_key:
            self.min_request_interval = 0.6  # 50 req/30sec = 1.67/sec ≈ 0.6s
        else:
            self.min_request_interval = 6.0  # 5 req/30sec = 0.167/sec ≈ 6s
    
    def get_cves_for_cpe(self, cpe: str, 
                        results_per_page: int = 100,
                        use_cache: bool = True) -> List[Dict[str, Any]]:
        """
        Get all CVEs affecting a CPE.
        
        Args:
            cpe: CPE 2.3 string (e.g., "cpe:2.3:a:nginx:nginx:1.18.0")
            results_per_page: Max results per page (default 100, max 2000)
            use_cache: Whether to use cached results
            
        Returns:
            List of CVE dictionaries with id, cvss_score, severity, description
        """
        # Check cache
        if use_cache and cpe in self._cache:
            cached_data = self._cache[cpe]
            cache_age = datetime.utcnow() - cached_data["cached_at"]
            if cache_age < timedelta(hours=24):  # 24-hour cache
                logger.info(f"Using cached CVE data for {cpe}")
                return cached_data["cves"]
        
        # Rate limit
        self._rate_limit()
        
        # Make request
        params = {
            "cpeName": cpe,
            "resultsPerPage": results_per_page
        }
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            response = requests.get(self.BASE_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = self._parse_response(data)
            
            # Cache results
            self._cache[cpe] = {
                "cves": cves,
                "cached_at": datetime.utcnow()
            }
            
            logger.info(f"Retrieved {len(cves)} CVEs for CPE: {cpe}")
            return cves
            
        except requests.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific CVE.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2021-44228")
            
        Returns:
            CVE details dict or None if not found
        """
        self._rate_limit()
        
        params = {"cveId": cve_id}
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            response = requests.get(self.BASE_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = self._parse_response(data)
            return cves[0] if cves else None
            
        except requests.RequestException as e:
            logger.error(f"Failed to get CVE {cve_id}: {e}")
            return None
    
    def _parse_response(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse NVD API response into simplified CVE list."""
        cves = []
        
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            
            # Extract CVE ID
            cve_id = cve_data.get("id", "")
            
            # Extract CVSS score (prefer v3.1, fallback to v3.0, then v2)
            cvss_score = None
            severity = None
            
            metrics = cve_data.get("metrics", {})
            
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_v31 = metrics["cvssMetricV31"][0]
                cvss_score = cvss_v31["cvssData"]["baseScore"]
                severity = cvss_v31["cvssData"]["baseSeverity"]
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_v30 = metrics["cvssMetricV30"][0]
                cvss_score = cvss_v30["cvssData"]["baseScore"]
                severity = cvss_v30["cvssData"]["baseSeverity"]
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_v2 = metrics["cvssMetricV2"][0]
                cvss_score = cvss_v2["cvssData"]["baseScore"]
                severity = cvss_v2["baseSeverity"]
            
            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract published date
            published = cve_data.get("published", "")
            
            cves.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity.lower() if severity else "unknown",
                "description": description,
                "published_date": published
            })
        
        return cves
    
    def _rate_limit(self):
        """Enforce rate limiting between requests."""
        if self.last_request_time:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_request_interval:
                sleep_time = self.min_request_interval - elapsed
                logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)
        
        self.last_request_time = time.time()


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("NVD API Client - Test")
    print("=" * 70)
    
    client = NVDAPIClient()
    
    # Test 1: Query CPE for nginx 1.18.0
    print("\n[Test 1] Query CVEs for nginx 1.18.0")
    print("-" * 50)
    
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    print(f"Querying: {cpe}")
    
    cves = client.get_cves_for_cpe(cpe)
    
    if cves:
        print(f"\nFound {len(cves)} CVEs:")
        for cve in cves[:5]:  # Show first 5
            print(f"  {cve['cve_id']:20} CVSS: {cve['cvss_score']:.1f} ({cve['severity'].upper()})")
            print(f"    {cve['description'][:80]}...")
    else:
        print("No CVEs found or API error")
    
    # Test 2: Get specific CVE details
    print("\n[Test 2] Get specific CVE details")
    print("-" * 50)
    
    cve_id = "CVE-2021-44228"  # Log4Shell
    print(f"Querying: {cve_id}")
    
    cve_details = client.get_cve_details(cve_id)
    
    if cve_details:
        print(f"\n{cve_details['cve_id']}:")
        print(f"  CVSS Score: {cve_details['cvss_score']}")
        print(f"  Severity: {cve_details['severity'].upper()}")
        print(f"  Description: {cve_details['description'][:100]}...")
    else:
        print("CVE not found or API error")
    
    print("\n[OK] NVD API client working!")
    print("\nNote: Set NVD_API_KEY environment variable for higher rate limits")
