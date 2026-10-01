"""
Unified Log Format (ULF) - OCSF-based schema for SOAR Platform
Enhanced with comprehensive validation
"""

from typing import Optional, List, Dict, Any
from pydantic import (
    BaseModel, 
    Field, 
    field_validator,
    model_validator,
    ConfigDict
)
from datetime import datetime, timezone
from enum import Enum
import re
import ipaddress


# Enums for standard values
class SeverityEnum(int, Enum):
    """OCSF Severity levels"""
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class StatusEnum(str, Enum):
    """Alert status"""
    UNKNOWN = "Unknown"
    NEW = "New"
    IN_PROGRESS = "In Progress"
    SUPPRESSED = "Suppressed"
    RESOLVED = "Resolved"


# OCSF Objects with validation
class Endpoint(BaseModel):
    """Network endpoint (IP, port, hostname)"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None
    
    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        """Validate IP address format"""
        if v is None:
            return v
        
        try:
            # Try to parse as IP address
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")
    
    @field_validator('port')
    @classmethod
    def validate_port(cls, v: Optional[int]) -> Optional[int]:
        """Validate port number range"""
        if v is None:
            return v
        
        if not (1 <= v <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {v}")
        
        return v
    
    @field_validator('mac')
    @classmethod
    def validate_mac(cls, v: Optional[str]) -> Optional[str]:
        """Validate MAC address format"""
        if v is None:
            return v
        
        # MAC address pattern: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        if not mac_pattern.match(v):
            raise ValueError(f"Invalid MAC address format: {v}")
        
        return v.upper()  # Normalize to uppercase


class User(BaseModel):
    """User information"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    name: Optional[str] = None
    uid: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        """Basic email validation"""
        if v is None:
            return v
        
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if not email_pattern.match(v):
            raise ValueError(f"Invalid email format: {v}")
        
        return v.lower()  # Normalize to lowercase


class Process(BaseModel):
    """Process information"""
    name: Optional[str] = None
    pid: Optional[int] = None
    cmd_line: Optional[str] = None
    parent_process: Optional[str] = None
    
    @field_validator('pid')
    @classmethod
    def validate_pid(cls, v: Optional[int]) -> Optional[int]:
        """Validate process ID"""
        if v is None:
            return v
        
        if v < 0:
            raise ValueError(f"Process ID cannot be negative: {v}")
        
        return v


class File(BaseModel):
    """File information"""
    name: Optional[str] = None
    path: Optional[str] = None
    hash: Optional[Dict[str, str]] = None
    size: Optional[int] = None
    
    @field_validator('hash')
    @classmethod
    def validate_hash(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        """Validate file hashes"""
        if v is None:
            return v
        
        valid_hash_types = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64,
            'sha512': 128
        }
        
        for hash_type, hash_value in v.items():
            hash_type_lower = hash_type.lower()
            if hash_type_lower in valid_hash_types:
                expected_len = valid_hash_types[hash_type_lower]
                if len(hash_value) != expected_len:
                    raise ValueError(
                        f"Invalid {hash_type} hash length: expected {expected_len}, got {len(hash_value)}"
                    )
                # Validate hex characters
                if not re.match(r'^[0-9a-fA-F]+$', hash_value):
                    raise ValueError(f"Hash must contain only hexadecimal characters: {hash_value}")
        
        return v
    
    @field_validator('size')
    @classmethod
    def validate_size(cls, v: Optional[int]) -> Optional[int]:
        """Validate file size"""
        if v is None:
            return v
        
        if v < 0:
            raise ValueError(f"File size cannot be negative: {v}")
        
        return v


class Product(BaseModel):
    """Product/vendor information"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    name: str
    vendor_name: str
    version: Optional[str] = None
    
    @field_validator('name', 'vendor_name')
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        """Ensure product name and vendor are not empty"""
        if not v or not v.strip():
            raise ValueError("Product name and vendor name cannot be empty")
        return v.strip()


def _utc_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalize datetimes to UTC-aware (avoids naive vs aware comparison errors)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class Metadata(BaseModel):
    """Event metadata"""
    version: str = "1.1.0"
    product: Product
    original_time: Optional[datetime] = None
    logged_time: Optional[datetime] = None

    @field_validator("original_time", "logged_time", mode="after")
    @classmethod
    def metadata_times_utc_aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        return _utc_aware(v)
    
    @field_validator('version')
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Validate OCSF version format"""
        version_pattern = re.compile(r'^\d+\.\d+\.\d+$')
        if not version_pattern.match(v):
            raise ValueError(f"Invalid OCSF version format: {v}. Expected format: X.Y.Z")
        return v


class Finding(BaseModel):
    """Detection finding details"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    title: str
    desc: Optional[str] = None
    uid: str
    types: List[str] = []
    src_url: Optional[str] = None
    
    @field_validator('title', 'uid')
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        """Ensure required fields are not empty"""
        if not v or not v.strip():
            raise ValueError("Finding title and UID cannot be empty")
        return v.strip()
    
    @field_validator('types')
    @classmethod
    def validate_mitre_techniques(cls, v: List[str]) -> List[str]:
        """Validate MITRE ATT&CK technique format"""
        if not v:
            return v
        
        mitre_pattern = re.compile(r'^T\d{4}(\.\d{3})?$')
        for technique in v:
            if not mitre_pattern.match(technique):
                raise ValueError(
                    f"Invalid MITRE ATT&CK technique format: {technique}. "
                    f"Expected format: TXXXX or TXXXX.XXX"
                )
        
        return v


class Resource(BaseModel):
    """Affected resource"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    name: str
    type: str
    uid: Optional[str] = None
    
    @field_validator('name', 'type')
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        """Ensure required fields are not empty"""
        if not v or not v.strip():
            raise ValueError("Resource name and type cannot be empty")
        return v.strip()


class Observable(BaseModel):
    """Observable indicators"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    name: str
    type: str
    value: str
    
    @field_validator('name', 'type', 'value')
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        """Ensure all fields are not empty"""
        if not v or not v.strip():
            raise ValueError("Observable fields cannot be empty")
        return v.strip()


# Main ULF Schema with comprehensive validation
class UnifiedLogFormat(BaseModel):
    """
    Unified Log Format based on OCSF Detection Finding class
    Enhanced with comprehensive validation
    """
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True  # Validate on attribute assignment too
    )
    
    # OCSF Required Fields
    class_uid: int = Field(2004, description="OCSF class UID (2004 = Detection Finding)")
    class_name: str = Field("Detection Finding", description="OCSF class name")
    category_uid: int = Field(2, description="OCSF category UID (2 = Findings)")
    category_name: str = Field("Findings", description="OCSF category name")
    
    # Core Fields
    severity_id: SeverityEnum
    severity: str
    activity_id: int
    activity_name: str
    type_uid: int
    time: int  # Unix timestamp (milliseconds)
    status: StatusEnum = StatusEnum.NEW
    
    # Metadata
    metadata: Metadata
    
    # Finding Details
    finding: Finding
    
    # Entities
    src_endpoint: Optional[Endpoint] = None
    dst_endpoint: Optional[Endpoint] = None
    actor: Optional[User] = None
    process: Optional[Process] = None
    file: Optional[File] = None
    
    # Context
    resources: List[Resource] = []
    observables: List[Observable] = []
    
    # Original Source Data
    raw_data: Optional[str] = Field(None, description="Original raw log")
    unmapped: Dict[str, Any] = Field(default_factory=dict, description="Unmapped fields")
    
    # SOAR Platform Fields
    alert_id: str = Field(..., description="SOAR platform unique alert ID")
    siem_source: str
    ingestion_timestamp: datetime
    processing_status: str = "pending"

    @field_validator("ingestion_timestamp", mode="after")
    @classmethod
    def ingestion_timestamp_utc_aware(cls, v: datetime) -> datetime:
        return _utc_aware(v)
    
    # Field Validators
    @field_validator('class_uid')
    @classmethod
    def validate_class_uid(cls, v: int) -> int:
        """Validate OCSF class UID"""
        # OCSF class UIDs are in range 1001-8999
        # Category UID (1-8) * 1000 + Event UID (1-99)
        if not (1001 <= v <= 8999):
            raise ValueError(f"Invalid OCSF class_uid: {v}. Must be between 1001-8999")
        return v
    
    @field_validator('category_uid')
    @classmethod
    def validate_category_uid(cls, v: int) -> int:
        """Validate OCSF category UID"""
        # OCSF has 8 categories (1-8)
        if not (1 <= v <= 8):
            raise ValueError(f"Invalid category_uid: {v}. Must be between 1-8")
        return v
    
    @field_validator('type_uid')
    @classmethod
    def validate_type_uid(cls, v: int) -> int:
        """Validate type_uid format"""
        # type_uid = class_uid * 100 + activity_id (1-99)
        # Valid range: 100101 to 899999
        if not (100101 <= v <= 899999):
            raise ValueError(f"Invalid type_uid: {v}. Must be between 100101-899999")
        return v
    
    @field_validator('time')
    @classmethod
    def validate_timestamp(cls, v: int) -> int:
        """Validate timestamp is reasonable"""
        # Check if timestamp is in milliseconds and within reasonable range
        # Jan 1, 2020 to 100 years in future
        min_timestamp = 1577836800000  # 2020-01-01
        max_timestamp = 4102444800000  # 2100-01-01
        
        if not (min_timestamp <= v <= max_timestamp):
            raise ValueError(
                f"Timestamp {v} is out of reasonable range. "
                f"Expected milliseconds between 2020 and 2100"
            )
        
        return v
    
    @field_validator('alert_id')
    @classmethod
    def validate_alert_id(cls, v: str) -> str:
        """Validate alert ID format"""
        # Expected format: SOAR-YYYYMMDD-XXXXXXXX
        pattern = re.compile(r'^SOAR-\d{8}-[0-9a-f]{8}$')
        if not pattern.match(v):
            raise ValueError(
                f"Invalid alert_id format: {v}. "
                f"Expected format: SOAR-YYYYMMDD-XXXXXXXX"
            )
        return v
    
    @field_validator('siem_source')
    @classmethod
    def validate_siem_source(cls, v: str) -> str:
        """Validate SIEM source"""
        if not v or not v.strip():
            raise ValueError("SIEM source cannot be empty")
        return v.strip().lower()
    
    # Model Validators (cross-field validation)
    @model_validator(mode='after')
    def validate_severity_consistency(self) -> 'UnifiedLogFormat':
        """Ensure severity_id and severity string match"""
        severity_map = {
            SeverityEnum.UNKNOWN: "Unknown",
            SeverityEnum.INFORMATIONAL: "Informational",
            SeverityEnum.LOW: "Low",
            SeverityEnum.MEDIUM: "Medium",
            SeverityEnum.HIGH: "High",
            SeverityEnum.CRITICAL: "Critical",
        }
        
        expected_severity = severity_map.get(self.severity_id)
        if self.severity != expected_severity:
            raise ValueError(
                f"Severity mismatch: severity_id={self.severity_id} "
                f"should map to '{expected_severity}', got '{self.severity}'"
            )
        
        return self
    
    @model_validator(mode='after')
    def validate_type_uid_consistency(self) -> 'UnifiedLogFormat':
        """Ensure type_uid matches class_uid and activity_id"""
        expected_type_uid = self.class_uid * 100 + self.activity_id
        if self.type_uid != expected_type_uid:
            raise ValueError(
                f"type_uid mismatch: expected {expected_type_uid} "
                f"(class_uid {self.class_uid} * 100 + activity_id {self.activity_id}), "
                f"got {self.type_uid}"
            )
        
        return self
    
    @model_validator(mode='after')
    def validate_has_observables_for_high_severity(self) -> 'UnifiedLogFormat':
        """High/Critical alerts should have observables (IOCs)"""
        if self.severity_id in [SeverityEnum.HIGH, SeverityEnum.CRITICAL]:
            if not self.observables and not self.src_endpoint and not self.dst_endpoint:
                # This is a warning, not an error
                self.unmapped['validation_warning'] = (
                    "High/Critical severity alert has no observables or endpoints"
                )
        
        return self
    
    @model_validator(mode='after')
    def validate_timestamp_consistency(self) -> 'UnifiedLogFormat':
        """Ensure ingestion_timestamp is not in the future (UTC-aware comparison)."""
        now = datetime.now(timezone.utc)
        ing = self.ingestion_timestamp
        if ing.tzinfo is None:
            ing = ing.replace(tzinfo=timezone.utc)
        else:
            ing = ing.astimezone(timezone.utc)
        if ing > now:
            raise ValueError(
                f"ingestion_timestamp cannot be in the future: {self.ingestion_timestamp}"
            )

        return self


# Validation helper functions
def validate_ulf(ulf_dict: Dict[str, Any]) -> tuple[UnifiedLogFormat, List[str]]:
    """
    Validate ULF dictionary and return object + warnings
    
    Returns:
        Tuple of (UnifiedLogFormat object, list of validation warnings)
    """
    warnings = []
    
    try:
        # Pydantic validation
        ulf = UnifiedLogFormat(**ulf_dict)
        
        # Additional quality checks (non-blocking)
        if not ulf.finding.desc or len(ulf.finding.desc) < 10:
            warnings.append("Finding description is very short or missing")
        
        if not ulf.resources:
            warnings.append("No affected resources specified")
        
        if ulf.severity_id >= SeverityEnum.HIGH and not ulf.finding.types:
            warnings.append("High severity alert has no MITRE ATT&CK techniques")
        
        if not ulf.raw_data:
            warnings.append("No raw log data stored (audit trail incomplete)")
        
        return ulf, warnings
        
    except Exception as e:
        raise ValueError(f"ULF validation failed: {str(e)}")


def get_validation_summary(ulf: UnifiedLogFormat) -> Dict[str, Any]:
    """
    Get a summary of what was validated
    """
    return {
        "alert_id": ulf.alert_id,
        "validation_passed": True,
        "checks": {
            "ocsf_compliance": {
                "class_uid": ulf.class_uid == 2004,
                "category_uid": ulf.category_uid == 2,
                "type_uid_format": 200401 <= ulf.type_uid <= 200499
            },
            "data_quality": {
                "timestamp_valid": True,
                "severity_consistent": True,
                "has_finding": ulf.finding is not None,
                "has_metadata": ulf.metadata is not None,
                "has_raw_data": ulf.raw_data is not None
            },
            "network_data": {
                "has_src_endpoint": ulf.src_endpoint is not None,
                "has_dst_endpoint": ulf.dst_endpoint is not None,
                "src_ip_valid": ulf.src_endpoint.ip is not None if ulf.src_endpoint else False,
                "dst_ip_valid": ulf.dst_endpoint.ip is not None if ulf.dst_endpoint else False
            },
            "context": {
                "has_observables": len(ulf.observables) > 0,
                "has_resources": len(ulf.resources) > 0,
                "has_mitre_techniques": len(ulf.finding.types) > 0
            }
        },
        "warnings": ulf.unmapped.get('validation_warning')
    }
