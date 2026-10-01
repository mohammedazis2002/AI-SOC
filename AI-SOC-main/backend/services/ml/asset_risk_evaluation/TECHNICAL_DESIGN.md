# Vulnerability & IOC Integration - Technical Design

## Problem Statement

OCSF alerts typically don't contain CVE IDs or CPE strings directly. We need a robust strategy to:
1. Extract or derive vulnerability information from alerts
2. Map assets to their vulnerabilities
3. Retrieve CVSS scores from authoritative sources
4. Correlate alerts with threat intelligence (IOCs)

---

## Part 1: Vulnerability Data Flow

### Architecture Overview

```
Alert → Asset Identification → Software Inventory → CPE Construction → NVD Query → CVE/CVSS Data
```

### Detailed Flow

#### Step 1: Asset Identification from Alert

**Input: OCSF Alert**
```json
{
  "device": {
    "hostname": "web-server-01",
    "ip": "10.0.1.50",
    "os": {
      "name": "Ubuntu",
      "version": "20.04"
    }
  }
}
```

**Extract:**
- `asset_id`: "web-server-01" (from hostname or IP)
- `os_info`: "Ubuntu 20.04"

#### Step 2: Software Inventory Lookup

**Query MongoDB `asset_inventory` collection:**
```python
asset_data = db.asset_inventory.find_one({
    "$or": [
        {"hostname": "web-server-01"},
        {"ip_address": "10.0.1.50"}
    ]
})

# Returns:
{
    "asset_id": "web-server-01",
    "hostname": "web-server-01",
    "ip_address": "10.0.1.50",
    "os": {
        "name": "Ubuntu",
        "version": "20.04",
        "cpe": "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*"
    },
    "installed_software": [
        {
            "name": "nginx",
            "version": "1.18.0",
            "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
        },
        {
            "name": "openssl",
            "version": "1.0.2k",
            "cpe": "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*"
        }
    ],
    "last_scanned": "2024-01-30T10:00:00Z"
}
```

#### Step 3: Query NVD API for CVEs

**For each CPE, query NVD:**

```python
import requests

def get_cves_for_cpe(cpe):
    """Query NVD API for CVEs affecting a CPE"""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cpeName": cpe,
        "resultsPerPage": 100
    }
    headers = {
        "apiKey": os.getenv("NVD_API_KEY")  # Optional, increases rate limit
    }
    
    response = requests.get(url, params=params, headers=headers)
    data = response.json()
    
    cves = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        
        # Extract CVSS score (v3.1 preferred, fallback to v2)
        cvss_data = cve_data.get("metrics", {})
        cvss_score = None
        severity = None
        
        if "cvssMetricV31" in cvss_data:
            cvss_v31 = cvss_data["cvssMetricV31"][0]
            cvss_score = cvss_v31["cvssData"]["baseScore"]
            severity = cvss_v31["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in cvss_data:
            cvss_v2 = cvss_data["cvssMetricV2"][0]
            cvss_score = cvss_v2["cvssData"]["baseScore"]
            severity = cvss_v2["baseSeverity"]
        
        cves.append({
            "cve_id": cve_data["id"],
            "cvss_score": cvss_score,
            "severity": severity,
            "description": cve_data.get("descriptions", [{}])[0].get("value"),
            "published_date": cve_data.get("published"),
            "cpe": cpe
        })
    
    return cves
```

**Example Response:**
```json
[
  {
    "cve_id": "CVE-2021-23017",
    "cvss_score": 8.1,
    "severity": "HIGH",
    "description": "nginx DNS resolver vulnerability...",
    "published_date": "2021-06-01T14:15:00",
    "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
  }
]
```

#### Step 4: Store in Database

```python
for cve in cves:
    db.asset_vulnerabilities.update_one(
        {
            "asset_id": "web-server-01",
            "cve_id": cve["cve_id"]
        },
        {
            "$set": {
                "cvss_score": cve["cvss_score"],
                "severity": cve["severity"],
                "description": cve["description"],
                "discovered_date": datetime.utcnow(),
                "patch_available": check_patch_availability(cve["cve_id"]),
                "cpe": cve["cpe"]
            }
        },
        upsert=True
    )
```

---

## Part 2: CPE Construction

### CPE Format

**CPE 2.3 Format:**
```
cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}
```

**Example:**
```
cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*
         │  │     │      │      └─ wildcards for unused fields
         │  │     │      └─ version
         │  │     └─ product name
         │  └─ vendor
         └─ part (a=application, o=operating system, h=hardware)
```

### Building CPE from Alert Data

```python
def build_cpe_from_alert(alert):
    """Construct CPE from OCSF alert metadata"""
    cpes = []
    
    # Operating System CPE
    os_info = alert.get("device", {}).get("os", {})
    if os_info:
        os_cpe = build_os_cpe(
            name=os_info.get("name"),
            version=os_info.get("version")
        )
        cpes.append(os_cpe)
    
    # Application CPE (if available)
    process = alert.get("process", {})
    if process:
        file_info = process.get("file", {})
        app_name = file_info.get("name")
        app_version = file_info.get("version")
        
        if app_name and app_version:
            app_cpe = build_application_cpe(
                product=app_name,
                version=app_version
            )
            cpes.append(app_cpe)
    
    return cpes


def build_os_cpe(name, version):
    """Build OS CPE string"""
    # Mapping of common OS names to CPE format
    os_mappings = {
        "ubuntu": ("canonical", "ubuntu_linux"),
        "centos": ("centos", "centos"),
        "windows": ("microsoft", "windows"),
        "red hat": ("redhat", "enterprise_linux"),
        "debian": ("debian", "debian_linux")
    }
    
    name_lower = name.lower()
    vendor = product = None
    
    for key, (v, p) in os_mappings.items():
        if key in name_lower:
            vendor, product = v, p
            break
    
    if not vendor:
        # Fallback: use name as both vendor and product
        vendor = product = name.lower().replace(" ", "_")
    
    return f"cpe:2.3:o:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def build_application_cpe(product, version, vendor=None):
    """Build application CPE string"""
    if not vendor:
        # Try to infer vendor from product name
        vendor = product.lower()
    
    product_clean = product.lower().replace(" ", "_")
    vendor_clean = vendor.lower().replace(" ", "_")
    
    return f"cpe:2.3:a:{vendor_clean}:{product_clean}:{version}:*:*:*:*:*:*:*"
```

---

## Part 3: Asset Inventory Population

### Source 1: Wazuh Syscollector

**Wazuh automatically collects software inventory:**

```python
def ingest_wazuh_syscollector(agent_id):
    """Ingest software inventory from Wazuh agent"""
    wazuh_api = WazuhAPI()
    
    # Get packages
    packages = wazuh_api.get_packages(agent_id)
    
    software_list = []
    for pkg in packages:
        cpe = build_application_cpe(
            product=pkg["name"],
            version=pkg["version"],
            vendor=pkg.get("vendor")
        )
        
        software_list.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "cpe": cpe
        })
    
    # Update asset inventory
    db.asset_inventory.update_one(
        {"wazuh_agent_id": agent_id},
        {"$set": {"installed_software": software_list}},
        upsert=True
    )
```

### Source 2: Manual Import

**CSV/JSON import for environments without automated collection:**

```python
def import_asset_inventory(csv_file):
    """Import asset inventory from CSV"""
    import csv
    
    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            asset = {
                "asset_id": row["AssetID"],
                "hostname": row["Hostname"],
                "ip_address": row["IP"],
                "os": {
                    "name": row["OS"],
                    "version": row["OSVersion"],
                    "cpe": build_os_cpe(row["OS"], row["OSVersion"])
                },
                "installed_software": [
                    {
                        "name": row["Software"],
                        "version": row["SoftwareVersion"],
                        "cpe": build_application_cpe(row["Software"], row["SoftwareVersion"])
                    }
                ]
            }
            
            db.asset_inventory.update_one(
                {"asset_id": asset["asset_id"]},
                {"$set": asset},
                upsert=True
            )
```

### Source 3: Vulnerability Scanner Results

**Ingest from Nessus/OpenVAS/Qualys:**

```python
def ingest_vulnerability_scan(scan_results):
    """Ingest vulnerability scan results (already contains CVEs)"""
    for finding in scan_results:
        asset_id = finding["asset_id"]
        
        for vuln in finding["vulnerabilities"]:
            db.asset_vulnerabilities.update_one(
                {
                    "asset_id": asset_id,
                    "cve_id": vuln["cve_id"]
                },
                {
                    "$set": {
                        "cvss_score": vuln["cvss_score"],
                        "severity": vuln["severity"],
                        "plugin_output": vuln["description"],
                        "discovered_date": datetime.utcnow(),
                        "scanner": "nessus"
                    }
                },
                upsert=True
            )
```

---

## Part 4: IOC Integration

### AlienVault OTX API

```python
import requests

class AlienVaultOTX:
    """AlienVault Open Threat Exchange integration"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
    
    def check_ip(self, ip_address):
        """Check if IP is malicious"""
        url = f"{self.base_url}/indicators/IPv4/{ip_address}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        
        response = requests.get(url, headers=headers)
        data = response.json()
        
        return {
            "ioc_type": "ip",
            "ioc_value": ip_address,
            "reputation_score": data.get("pulse_info", {}).get("count", 0),
            "threat_level": "high" if data.get("pulse_info", {}).get("count", 0) > 5 else "low",
            "campaigns": [p["name"] for p in data.get("pulse_info", {}).get("pulses", [])]
        }
    
    def check_domain(self, domain):
        """Check if domain is malicious"""
        url = f"{self.base_url}/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        
        response = requests.get(url, headers=headers)
        data = response.json()
        
        return {
            "ioc_type": "domain",
            "ioc_value": domain,
            "reputation_score": data.get("pulse_info", {}).get("count", 0),
            "threat_level": "high" if data.get("pulse_info", {}).get("count", 0) > 3 else "low"
        }
    
    def check_file_hash(self, file_hash):
        """Check if file hash is malicious"""
        url = f"{self.base_url}/indicators/file/{file_hash}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        
        response = requests.get(url, headers=headers)
        data = response.json()
        
        return {
            "ioc_type": "file_hash",
            "ioc_value": file_hash,
            "malicious": data.get("pulse_info", {}).get("count", 0) > 0,
            "malware_families": [p.get("malware_families", []) for p in data.get("pulse_info", {}).get("pulses", [])]
        }
```

### Usage in Alert Processing

```python
def enrich_alert_with_iocs(alert):
    """Enrich alert with IOC threat intelligence"""
    otx = AlienVault OTX(api_key=os.getenv("OTX_API_KEY"))
    
    threat_score = 0
    ioc_hits = []
    
    # Check IP addresses
    src_ip = alert.get("src_endpoint", {}).get("ip")
    dst_ip = alert.get("dst_endpoint", {}).get("ip")
    
    if src_ip:
        ioc_data = otx.check_ip(src_ip)
        if ioc_data["reputation_score"] > 5:
            threat_score += 50
            ioc_hits.append(ioc_data)
    
    # Check domains
    domain = alert.get("http_request", {}).get("url_hostname")
    if domain:
        ioc_data = otx.check_domain(domain)
        if ioc_data["reputation_score"] > 3:
            threat_score += 40
            ioc_hits.append(ioc_data)
    
    # Check file hashes
    file_hash = alert.get("file", {}).get("hashes", {}).get("sha256")
    if file_hash:
        ioc_data = otx.check_file_hash(file_hash)
        if ioc_data["malicious"]:
            threat_score += 100  # Known malware
            ioc_hits.append(ioc_data)
    
    return {
        "threat_intel_score": min(threat_score, 100),
        "ioc_matches": ioc_hits
    }
```

---

## Part 5: Complete Risk Calculation Flow

```python
def calculate_asset_risk(asset_id, alert=None):
    """Calculate complete asset risk score"""
    
    # 1. Get asset profile
    asset = db.asset_inventory.find_one({"asset_id": asset_id})
    if not asset:
        # Create basic profile from alert
        asset = create_asset_from_alert(alert)
    
    # 2. Calculate criticality score (25%)
    criticality_score = get_criticality_score(asset)
    
    # 3. Calculate vulnerability score (30%)
    vulnerabilities = list(db.asset_vulnerabilities.find({
        "asset_id": asset_id
    }))
    vulnerability_score = calculate_vulnerability_score(vulnerabilities)
    
    # 4. Calculate exposure score (20%)
    exposure_score = calculate_exposure_score(asset)
    
    # 5. Calculate incident history score (15%)
    incidents = list(db.asset_incidents.find({
        "asset_id": asset_id,
        "timestamp": {"$gte": datetime.utcnow() - timedelta(days=90)}
    }))
    incident_score = calculate_incident_score(incidents)
    
    # 6. Calculate threat intelligence score (10%)
    threat_score = 0
    if alert:
        threat_data = enrich_alert_with_iocs(alert)
        threat_score = threat_data["threat_intel_score"]
    
    # Weighted sum
    risk_score = (
        (criticality_score * 0.25) +
        (vulnerability_score * 0.30) +
        (exposure_score * 0.20) +
        (incident_score * 0.15) +
        (threat_score * 0.10)
    )
    
    return {
        "asset_id": asset_id,
        "risk_score": round(risk_score, 2),
        "risk_level": get_risk_level(risk_score),
        "components": {
            "criticality": criticality_score,
            "vulnerabilities": vulnerability_score,
            "exposure": exposure_score,
            "incident_history": incident_score,
            "threat_intel": threat_score
        }
    }
```

---

## Summary

**Vulnerability Data:**
1. ✅ We DON'T calculate CVSS - we retrieve from NVD
2. ✅ We construct CPE from device metadata
3. ✅ We query NVD API: CPE → CVE list → CVSS scores
4. ✅ We ingest from vulnerability scanners when available

**IOC Data:**
1. ✅ AlienVault OTX API for IP/domain/hash reputation
2. ✅ Abuse.ch feeds for malware IOCs
3. ✅ Real-time enrichment during alert processing

**Data Flow:**
```
Alert → Asset ID → Asset Inventory → CPE → NVD Query → CVE/CVSS
Alert → Extract IOCs → OTX Query → Threat Intel Score
```

This gives us everything needed for accurate risk scoring!
