"""
SentinelOne Alert to ULF Mapper
"""

from datetime import datetime
from typing import Dict, Any, Tuple, List
import uuid

from schemas.ulf_schema import (
    UnifiedLogFormat, SeverityEnum, StatusEnum,
    Metadata, Product, Finding, Endpoint,
    validate_ulf
)


class SentinelOneMapper:
    """Maps SentinelOne alerts to ULF format"""
    
    # SentinelOne confidence to OCSF severity mapping
    SEVERITY_MAPPING = {
        "malicious": (SeverityEnum.CRITICAL, "Critical"),
        "suspicious": (SeverityEnum.HIGH, "High"),
        "info": (SeverityEnum.INFORMATIONAL, "Informational"),
        "unknown": (SeverityEnum.UNKNOWN, "Unknown")
    }
    
    @staticmethod
    def map_alert(s1_alert: Dict[str, Any]) -> Tuple[UnifiedLogFormat, List[str], Dict[str, Any]]:
        """Transform SentinelOne alert to ULF"""
        
        threat_info = s1_alert.get("threatInfo", {})
        agent_info = s1_alert.get("agentRealtimeInfo", {})
        
        # Map severity
        confidence = threat_info.get("confidenceLevel", "unknown")
        severity_id, severity_str = SentinelOneMapper.SEVERITY_MAPPING.get(
            confidence,
            (SeverityEnum.UNKNOWN, "Unknown")
        )
        
        # Generate alert ID
        alert_id = f"SOAR-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        
        # Extract IPs from indicators
        src_endpoint = None
        indicators = s1_alert.get("indicators", [])
        for indicator in indicators:
            if indicator.get("category") == "Network":
                src_endpoint = Endpoint(ip=indicator.get("value"))
                break
        
        # Build ULF
        ulf_dict = {
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": severity_id,
            "severity": severity_str,
            "activity_id": 1,
            "activity_name": "Create",
            "type_uid": 200401,
            "time": int(datetime.utcnow().timestamp() * 1000),
            "status": StatusEnum.NEW,
            "metadata": Metadata(
                version="1.1.0",
                product=Product(
                    name="SentinelOne",
                    vendor_name="SentinelOne"
                )
            ),
            "finding": Finding(
                title=threat_info.get("threatName", "Unknown Threat"),
                desc=str(s1_alert),
                uid=s1_alert.get("id", alert_id),
                types=[]  # Could map to MITRE
            ),
            "src_endpoint": src_endpoint,
            "alert_id": alert_id,
            "siem_source": "sentinelone",
            "ingestion_timestamp": datetime.utcnow(),
            "processing_status": "pending",
            "raw_data": str(s1_alert),
            "unmapped": {
                "s1_confidence": confidence,
                "s1_agent": agent_info.get("agentComputerName")
            }
        }
        
        ulf, warnings = validate_ulf(ulf_dict)
        from schemas.ulf_schema import get_validation_summary
        summary = get_validation_summary(ulf)
        
        return ulf, warnings, summary
