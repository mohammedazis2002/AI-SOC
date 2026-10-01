"""
Wazuh Alert to ULF (OCSF) Mapper with Validation
"""

from datetime import datetime
from typing import Dict, Any, Tuple, List
import uuid

from schemas.ulf_schema import (
    UnifiedLogFormat,
    SeverityEnum,
    StatusEnum,
    Metadata,
    Product,
    Finding,
    Resource,
    Observable,
    Endpoint,
    User,
    validate_ulf,
    get_validation_summary
)
from pydantic import ValidationError
from services.classification.event_classifier import event_classifier
from services.ingestion.extraction_helpers import extract_all, get_extraction_result


class WazuhToULFMapper:
    """Maps Wazuh alerts to Unified Log Format (OCSF) with validation"""
    
    # Wazuh rule level to OCSF severity mapping
    SEVERITY_MAPPING = {
        0: (SeverityEnum.INFORMATIONAL, "Informational"),
        1: (SeverityEnum.INFORMATIONAL, "Informational"),
        2: (SeverityEnum.INFORMATIONAL, "Informational"),
        3: (SeverityEnum.LOW, "Low"),
        4: (SeverityEnum.LOW, "Low"),
        5: (SeverityEnum.LOW, "Low"),
        6: (SeverityEnum.MEDIUM, "Medium"),
        7: (SeverityEnum.MEDIUM, "Medium"),
        8: (SeverityEnum.MEDIUM, "Medium"),
        9: (SeverityEnum.HIGH, "High"),
        10: (SeverityEnum.HIGH, "High"),
        11: (SeverityEnum.HIGH, "High"),
        12: (SeverityEnum.CRITICAL, "Critical"),
        13: (SeverityEnum.CRITICAL, "Critical"),
        14: (SeverityEnum.CRITICAL, "Critical"),
        15: (SeverityEnum.CRITICAL, "Critical"),
    }
    
    @staticmethod
    def map_alert(wazuh_alert: Dict[str, Any]) -> Tuple[UnifiedLogFormat, List[str], Dict[str, Any]]:
        """
        Transform Wazuh alert to ULF format with validation
        
        Args:
            wazuh_alert: Raw Wazuh alert dictionary
            
        Returns:
            Tuple of (UnifiedLogFormat object, validation warnings, validation summary)
            
        Raises:
            ValidationError: If alert fails validation
        """
        
        # Extract severity
        rule_level = wazuh_alert.get("rule", {}).get("level", 0)
        severity_id, severity_str = WazuhToULFMapper.SEVERITY_MAPPING.get(
            rule_level, 
            (SeverityEnum.UNKNOWN, "Unknown")
        )
        
        # Parse timestamp
        timestamp_str = wazuh_alert.get("timestamp", "")
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("+0000", "+00:00"))
            time_ms = int(timestamp.timestamp() * 1000)
        except:
            timestamp = datetime.utcnow()
            time_ms = int(timestamp.timestamp() * 1000)
        
        # Generate SOAR alert ID
        alert_id = f"SOAR-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        
        # Build metadata
        metadata = Metadata(
            version="1.1.0",
            product=Product(
                name="Wazuh",
                vendor_name="Wazuh Inc",
                version="4.x"
            ),
            original_time=timestamp,
            logged_time=datetime.utcnow()
        )
        
        # Build finding
        rule = wazuh_alert.get("rule", {})
        mitre = rule.get("mitre", {})
        mitre_ids = mitre.get("id", [])
        
        finding = Finding(
            title=rule.get("description", "Unknown Alert"),
            desc=wazuh_alert.get("full_log", ""),
            uid=wazuh_alert.get("id", alert_id),
            types=mitre_ids,
            src_url=f"https://wazuh-manager/app/wazuh#/manager/ruleset?tab=rules&redirectRule={rule.get('id')}"
        )
        
        # Extract source endpoint (with validation)
        src_endpoint = None
        data = wazuh_alert.get("data", {})
        if "srcip" in data:
            try:
                src_endpoint = Endpoint(
                    ip=data.get("srcip"),
                    port=int(data.get("srcport")) if data.get("srcport") else None,
                    hostname=data.get("srchost")
                )
            except ValidationError as e:
                print(f"Warning: Invalid source endpoint data: {e}")
        
        # Extract destination endpoint (agent)
        agent = wazuh_alert.get("agent", {})
        dst_endpoint = None
        if agent.get("ip"):
            try:
                dst_endpoint = Endpoint(
                    ip=agent.get("ip"),
                    hostname=agent.get("name")
                )
            except ValidationError as e:
                print(f"Warning: Invalid destination endpoint data: {e}")
        
        # Extract user
        actor = None
        if "dstuser" in data:
            actor = User(name=data.get("dstuser"))
        
        # Build resources list
        resources = []
        if agent.get("name"):
            resources.append(Resource(
                name=agent.get("name"),
                type="Server",
                uid=agent.get("id")
            ))
        
        # Build observables
        observables = []
        if src_endpoint and src_endpoint.ip:
            observables.append(Observable(
                name="src_ip",
                type="IP Address",
                value=src_endpoint.ip
            ))
        if "dstuser" in data:
            observables.append(Observable(
                name="username",
                type="User Name",
                value=data["dstuser"]
            ))
        
        # Use EventClassifier for dynamic OCSF classification
        full_log = wazuh_alert.get("full_log", "")
        classification = event_classifier.classify({"message": full_log, **wazuh_alert})
        
        # Use extraction helpers for additional field extraction from full_log
        extracted = get_extraction_result(full_log) if full_log else {}
        
        # Enhance source endpoint with extracted data if not in Wazuh data
        if not src_endpoint and extracted.get("source_ip"):
            try:
                src_endpoint = Endpoint(
                    ip=extracted.get("source_ip"),
                    port=extracted.get("source_port")
                )
            except ValidationError:
                pass
        
        # Enhance actor with extracted username if not in Wazuh data
        if not actor and extracted.get("username"):
            actor = User(name=extracted.get("username"))
            observables.append(Observable(
                name="username",
                type="User Name",
                value=extracted.get("username")
            ))
        
        # Build unmapped data
        unmapped = {
            "wazuh_rule_id": rule.get("id"),
            "wazuh_rule_level": rule_level,
            "wazuh_rule_groups": rule.get("groups", []),
            "wazuh_agent_id": agent.get("id"),
            "wazuh_location": wazuh_alert.get("location"),
            "wazuh_decoder": wazuh_alert.get("decoder", {}).get("name"),
            "classification_method": classification.method,
            "classification_confidence": classification.confidence
        }
        
        # Create ULF dictionary with dynamic classification
        # Map short category names to full OCSF category names
        category_name_map = {
            "iam": "Identity & Access Management",
            "identity": "Identity & Access Management",
            "network": "Network Activity",
            "findings": "Findings",
            "system": "System Activity",
            "application": "Application Activity",
            "discovery": "Discovery",
        }
        full_category_name = category_name_map.get(
            classification.category.lower(), 
            classification.caption if classification.caption else classification.category
        )
        
        ulf_dict = {
            "class_uid": classification.class_uid,
            "class_name": classification.class_name,
            "category_uid": classification.category_uid,
            "category_name": full_category_name,
            "severity_id": severity_id,
            "severity": severity_str,
            "activity_id": 1,
            "activity_name": "Create",
            "type_uid": classification.class_uid * 100 + 1,
            "time": time_ms,
            "status": StatusEnum.NEW,
            "metadata": metadata,
            "finding": finding,
            "src_endpoint": src_endpoint,
            "dst_endpoint": dst_endpoint,
            "actor": actor,
            "resources": resources,
            "observables": observables,
            "raw_data": str(wazuh_alert),
            "unmapped": unmapped,
            "alert_id": alert_id,
            "siem_source": "wazuh",
            "ingestion_timestamp": datetime.utcnow(),
            "processing_status": "pending"
        }
        
        # Validate and create ULF object
        try:
            ulf, warnings = validate_ulf(ulf_dict)
            summary = get_validation_summary(ulf)
            
            return ulf, warnings, summary
            
        except ValidationError as e:
            # Re-raise with more context
            raise ValidationError(f"Wazuh alert validation failed: {e}")
    
    @staticmethod
    def validate_wazuh_alert(alert: Dict[str, Any]) -> bool:
        """Validate that the input is a valid Wazuh alert"""
        required_fields = ["timestamp", "rule", "id"]
        return all(field in alert for field in required_fields)


# Usage example with validation
if __name__ == "__main__":
    import json
    
    # Load example Wazuh alert
    with open("backend/examples/wazuh_alert_example.json", "r") as f:
        wazuh_alert = json.load(f)
    
    # Map to ULF with validation
    try:
        mapper = WazuhToULFMapper()
        ulf, warnings, summary = mapper.map_alert(wazuh_alert)
        
        print("✅ VALIDATION SUCCESSFUL")
        print("\n" + "=" * 80)
        print("ULF OUTPUT:")
        print("=" * 80)
        print(json.dumps(ulf.model_dump(), indent=2, default=str))
        
        if warnings:
            print("\n" + "=" * 80)
            print("⚠️  VALIDATION WARNINGS:")
            print("=" * 80)
            for warning in warnings:
                print(f"  • {warning}")
        
        print("\n" + "=" * 80)
        print("VALIDATION SUMMARY:")
        print("=" * 80)
        print(json.dumps(summary, indent=2))
        
    except ValidationError as e:
        print("❌ VALIDATION FAILED")
        print(f"\nErrors:\n{e}")
