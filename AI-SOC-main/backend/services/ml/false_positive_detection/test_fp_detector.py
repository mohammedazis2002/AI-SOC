"""
End-to-End Tests for False Positive Detector

Tests rule-based detection with realistic scenarios
"""

import logging
from datetime import datetime
from pymongo import MongoClient

from backend.services.ml.fp_detector import FalsePositiveDetector

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_scenario(name, alert, expected_fp_range, expected_action):
    """
    Test a single FP detection scenario
    
    Args:
        name: Scenario name
        alert: Alert dictionary
        expected_fp_range: (min, max) expected FP score
        expected_action: Expected recommendation action
    """
    logger.info("\n" + "="*60)
    logger.info(f"TEST: {name}")
    logger.info("="*60)
    
    db = MongoClient()['soar_db']
    detector = FalsePositiveDetector(db_client=db)
    result = detector.detect(alert)
    
    logger.info(f"\n📊 Results:")
    logger.info(f"  FP Score: {result['fp_score']:.2f}")
    logger.info(f"  Confidence: {result['confidence']:.2f}")
    logger.info(f"  Method: {result['method']}")
    logger.info(f"  Recommendation: {result['recommendation']['action']}")
    
    if result['reasons']:
        logger.info(f"\n💡 Reasons:")
        for reason in result['reasons']:
            logger.info(f"  - {reason}")
    
    # Validate
    min_fp, max_fp = expected_fp_range
    
    if min_fp <= result['fp_score'] <= max_fp:
        logger.info(f"\n✅ PASS - FP score in expected range [{min_fp}, {max_fp}]")
    else:
        logger.info(f"\n❌ FAIL - FP score {result['fp_score']:.2f} not in range [{min_fp}, {max_fp}]")
        return False
    
    if result['recommendation']['action'] == expected_action:
        logger.info(f"✅ PASS - Recommendation matches expected: {expected_action}")
    else:
        logger.info(f"❌ FAIL - Expected '{expected_action}', got '{result['recommendation']['action']}'")
        return False
    
    return True


def run_fp_tests():
    """Run all FP detector tests"""
    
    logger.info("\n" + "="*60)
    logger.info("FALSE POSITIVE DETECTOR - TEST SUITE")
    logger.info("="*60)
    
    passed = 0
    total = 0
    
    # Scenario 1: Vulnerability Scanner - High Confidence FP
    total += 1
    alert1 = {
        "alert_id": "test_fp_001",
        "time": int(datetime.now().timestamp() * 1000),
        "severity_id": 2,
        "class_uid": 4001,
        "finding": {
            "title": "Network scan detected from Nessus scanner",
            "desc": "Port scan activity detected",
            "uid": "test_001"
        },
        "src_endpoint": {
            "ip": "10.0.0.50",
            "hostname": "nessus-scanner-01"
        },
        "dst_endpoint": {
            "hostname": "web-server-01"
        },
        "unmapped": {
            "wazuh_rule_id": 40111,
            "wazuh_rule_level": 7
        }
    }
    
    if test_scenario(
        "Vulnerability Scanner Traffic",
        alert1,
        (0.8, 1.0),  # High FP score expected
        "auto_close"  # Should recommend auto-close
    ):
        passed += 1
    
    # Scenario 2: Test Environment - Likely FP
    total += 1
    alert2 = {
        "alert_id": "test_fp_002",
        "time": int(datetime.now().timestamp() * 1000),
        "severity_id": 3,
        "class_uid": 3002,
        "finding": {
            "title": "Failed login attempt on test server",
            "desc": "Multiple failed passwords on dev-server-02",
            "uid": "test_002"
        },
        "dst_endpoint": {
            "hostname": "dev-server-02"
        },
        "actor": {
            "user": {"name": "testuser", "type_id": 1}
        },
        "unmapped": {
            "wazuh_rule_id": 5710,
            "wazuh_rule_level": 8
        }
    }
    
    if test_scenario(
        "Failed Login on Dev Environment",
        alert2,
        (0.7, 0.9),  # Moderate-high FP score
        "suppress"  # Should suppress or auto-close
    ):
        passed += 1
    
    # Scenario 3: Production Critical - True Positive
    total += 1
    alert3 = {
        "alert_id": "test_fp_003",
        "time": int(datetime.now().timestamp() * 1000),
        "severity_id": 4,  # Critical
        "class_uid": 2004,
        "finding": {
            "title": "Malware detected on production server",
            "desc": "Ransomware behavior detected",
            "uid": "test_003"
        },
        "dst_endpoint": {
            "hostname": "prod-db-01"
        },
        "enrichments": {
            "mitre": {
                "dominant_tactic": "impact"
            },
            "threat_intel": {
                "virustotal": {
                    "malicious": 45,
                    "total": 70
                }
            }
        },
        "unmapped": {
            "wazuh_rule_id": 55002,
            "wazuh_rule_level": 15
        }
    }
    
    if test_scenario(
        "Critical Malware on Production",
        alert3,
        (0.0, 0.3),  # Low FP score
        "investigate"  # Must investigate (safety net)
    ):
        passed += 1
    
    # Scenario 4: Service Account Internal Activity - Likely FP
    total += 1
    alert4 = {
        "alert_id": "test_fp_004",
        "time": int(datetime.now().timestamp() * 1000),
        "severity_id": 1,  # Informational
        "class_uid": 3002,
        "finding": {
            "title": "Service account login",
            "desc": "Automated service account access",
            "uid": "test_004"
        },
        "src_endpoint": {
            "ip": "192.168.1.100"
        },
        "actor": {
            "user": {
                "name": "svc_backup",
                "type_id": 3  # Service account
            }
        },
        "unmapped": {
            "wazuh_rule_id": 5501,
            "wazuh_rule_level": 3
        }
    }
    
    if test_scenario(
        "Service Account Internal Activity",
        alert4,
        (0.5, 0.8),  # Moderate FP score
        "deprioritize"  # Low priority or suppress
    ):
        passed += 1
    
    # Scenario 5: External Attack - True Positive
    total += 1
    alert5 = {
        "alert_id": "test_fp_005",
        "time": int(datetime.now().timestamp() * 1000),
        "severity_id": 3,
        "class_uid": 3002,
        "finding": {
            "title": "Brute force attack from external IP",
            "desc": "Multiple failed logins from 185.220.101.45",
            "uid": "test_005"
        },
        "src_endpoint": {
            "ip": "185.220.101.45"  # External IP
        },
        "dst_endpoint": {
            "hostname": "web-server-01"
        },
        "enrichments": {
            "mitre": {
                "dominant_tactic": "credential_access"
            },
            "threat_intel": {
                "abuseipdb": {
                    "confidence": 95,
                    "reported_count": 47
                }
            }
        },
        "unmapped": {
            "wazuh_rule_id": 5712,
            "wazuh_rule_level": 10
        }
    }
    
    if test_scenario(
        "External Brute Force Attack",
        alert5,
        (0.0, 0.4),  # Low FP score
        "investigate"  # Should investigate
    ):
        passed += 1
    
    # Summary
    logger.info("\n" + "="*60)
    logger.info("TEST SUMMARY")
    logger.info("="*60)
    logger.info(f"✅ Passed: {passed}/{total} scenarios")
    
    if passed == total:
        logger.info("\n🎉 All tests passed! FP Detector is working correctly.")
    else:
        logger.warning(f"\n⚠️  {total - passed} test(s) failed.")
    
    return passed == total


if __name__ == "__main__":
    success = run_fp_tests()
    exit(0 if success else 1)
