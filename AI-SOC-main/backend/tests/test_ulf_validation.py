"""
Test suite for ULF validation
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from schemas.ulf_schema import (
    UnifiedLogFormat,
    SeverityEnum,
    StatusEnum,
    Metadata,
    Product,
    Finding,
    Endpoint,
    User,
    validate_ulf,
    get_validation_summary
)


def create_valid_ulf() -> dict:
    """Helper to create a valid ULF dictionary"""
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "severity_id": SeverityEnum.HIGH,
        "severity": "High",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "time": 1703596800000,
        "status": StatusEnum.NEW,
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "Wazuh",
                "vendor_name": "Wazuh Inc"
            }
        },
        "finding": {
            "title": "SSH Brute Force Attack",
            "desc": "Multiple failed login attempts detected",
            "uid": "wazuh-123",
            "types": ["T1110"]
        },
        "src_endpoint": {
            "ip": "192.168.1.100",
            "port": 12345
        },
        "alert_id": "SOAR-20241230-12345678",
        "siem_source": "wazuh",
        "ingestion_timestamp": datetime.utcnow(),
        "processing_status": "pending"
    }


class TestEndpointValidation:
    """Test Endpoint validation"""
    
    def test_valid_ip(self):
        """Valid IP addresses should pass"""
        endpoint = Endpoint(ip="192.168.1.1")
        assert endpoint.ip == "192.168.1.1"
        
        endpoint = Endpoint(ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert endpoint.ip is not None
    
    def test_invalid_ip(self):
        """Invalid IP addresses should fail"""
        with pytest.raises(ValidationError) as exc_info:
            Endpoint(ip="999.999.999.999")
        assert "Invalid IP address" in str(exc_info.value)
        
        with pytest.raises(ValidationError):
            Endpoint(ip="not-an-ip")
    
    def test_valid_port(self):
        """Valid port numbers should pass"""
        endpoint = Endpoint(port=80)
        assert endpoint.port == 80
        
        endpoint = Endpoint(port=65535)
        assert endpoint.port == 65535
    
    def test_invalid_port(self):
        """Invalid port numbers should fail"""
        with pytest.raises(ValidationError) as exc_info:
            Endpoint(port=0)
        assert "Port must be between 1 and 65535" in str(exc_info.value)
        
        with pytest.raises(ValidationError):
            Endpoint(port=70000)
    
    def test_valid_mac(self):
        """Valid MAC addresses should pass"""
        endpoint = Endpoint(mac="00:11:22:33:44:55")
        assert endpoint.mac == "00:11:22:33:44:55"
        
        endpoint = Endpoint(mac="AA-BB-CC-DD-EE-FF")
        assert endpoint.mac == "AA-BB-CC-DD-EE-FF"
    
    def test_invalid_mac(self):
        """Invalid MAC addresses should fail"""
        with pytest.raises(ValidationError) as exc_info:
            Endpoint(mac="invalid-mac")
        assert "Invalid MAC address" in str(exc_info.value)


class TestUserValidation:
    """Test User validation"""
    
    def test_valid_email(self):
        """Valid emails should pass"""
        user = User(email="admin@example.com")
        assert user.email == "admin@example.com"
    
    def test_invalid_email(self):
        """Invalid emails should fail"""
        with pytest.raises(ValidationError) as exc_info:
            User(email="not-an-email")
        assert "Invalid email format" in str(exc_info.value)


class TestFindingValidation:
    """Test Finding validation"""
    
    def test_valid_mitre_techniques(self):
        """Valid MITRE techniques should pass"""
        finding = Finding(
            title="Test",
            uid="123",
            types=["T1110", "T1078.001"]
        )
        assert len(finding.types) == 2
    
    def test_invalid_mitre_techniques(self):
        """Invalid MITRE techniques should fail"""
        with pytest.raises(ValidationError) as exc_info:
            Finding(
                title="Test",
                uid="123",
                types=["INVALID", "T9999999"]
            )
        assert "Invalid MITRE ATT&CK technique" in str(exc_info.value)


class TestULFValidation:
    """Test UnifiedLogFormat validation"""
    
    def test_valid_ulf(self):
        """Valid ULF should pass all validations"""
        ulf_dict = create_valid_ulf()
        ulf = UnifiedLogFormat(**ulf_dict)
        
        assert ulf.alert_id == "SOAR-20241230-12345678"
        assert ulf.severity == "High"
        assert ulf.class_uid == 2004
    
    def test_severity_consistency(self):
        """Severity ID and string must match"""
        ulf_dict = create_valid_ulf()
        ulf_dict["severity_id"] = SeverityEnum.LOW
        ulf_dict["severity"] = "High"  # Mismatch!
        
        with pytest.raises(ValidationError) as exc_info:
            UnifiedLogFormat(**ulf_dict)
        assert "Severity mismatch" in str(exc_info.value)
    
    def test_type_uid_consistency(self):
        """type_uid must match class_uid and activity_id"""
        ulf_dict = create_valid_ulf()
        ulf_dict["type_uid"] = 999999  # Invalid
        
        with pytest.raises(ValidationError) as exc_info:
            UnifiedLogFormat(**ulf_dict)
        
        
        # FIX: Check for the actual error message from Pydantic
        error_message = str(exc_info.value).lower()
        # Just verify that ValidationError was raised and mentions type_uid
        assert "type_uid" in error_message
        # Verify it's specifically about invalid value for Detection Finding
        assert "invalid" in error_message or "detection finding" in error_message
    
    def test_invalid_timestamp(self):
        """Timestamp must be reasonable"""
        ulf_dict = create_valid_ulf()
        ulf_dict["time"] = 999  # Too old (seconds instead of milliseconds)
        
        with pytest.raises(ValidationError) as exc_info:
            UnifiedLogFormat(**ulf_dict)
        assert "out of reasonable range" in str(exc_info.value)
    
    def test_invalid_alert_id(self):
        """Alert ID must match format"""
        ulf_dict = create_valid_ulf()
        ulf_dict["alert_id"] = "invalid-id"
        
        with pytest.raises(ValidationError) as exc_info:
            UnifiedLogFormat(**ulf_dict)
        assert "Invalid alert_id format" in str(exc_info.value)
    
    def test_empty_siem_source(self):
        """SIEM source cannot be empty"""
        ulf_dict = create_valid_ulf()
        ulf_dict["siem_source"] = ""
        
        with pytest.raises(ValidationError) as exc_info:
            UnifiedLogFormat(**ulf_dict)
        assert "SIEM source cannot be empty" in str(exc_info.value)


class TestValidationHelpers:
    """Test validation helper functions"""
    
    def test_validate_ulf_with_warnings(self):
        """Validate ULF and get warnings"""
        ulf_dict = create_valid_ulf()
        ulf_dict["resources"] = []  # No resources
        
        ulf, warnings = validate_ulf(ulf_dict)
        
        assert ulf is not None
        assert len(warnings) > 0
        assert any("resources" in w.lower() for w in warnings)
    
    def test_validation_summary(self):
        """Get validation summary"""
        ulf_dict = create_valid_ulf()
        ulf = UnifiedLogFormat(**ulf_dict)
        
        summary = get_validation_summary(ulf)
        
        assert summary["validation_passed"] is True
        assert summary["checks"]["ocsf_compliance"]["class_uid"] is True
        assert summary["checks"]["data_quality"]["has_finding"] is True


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
