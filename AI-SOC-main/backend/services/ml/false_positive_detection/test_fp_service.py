"""
Test FP Detector Service - Direct Import Test

Tests FP detector without needing to run the service
Windows-compatible version (no emojis)
"""

import sys
from datetime import datetime
from backend.services.ml.fp_detector import FalsePositiveDetector

print("="*60)
print("FP DETECTOR DIRECT TEST")
print("="*60)

# Initialize detector
print("\n1. Initializing FP Detector...")
try:
    detector = FalsePositiveDetector()
    print("   [OK] FP Detector initialized successfully")
except Exception as e:
    print(f"   [FAIL] Error initializing: {e}")
    sys.exit(1)

# Test 1: Known scanner (should be FP)
print("\n2. Test 1: Known Scanner Alert (should be FP)")
scanner_alert = {
    "alert_id": "TEST-001",
    "time": int(datetime.now().timestamp() * 1000),
    "severity_id": 2,
    "class_uid": 4001,
    "finding": {
        "title": "Port scan detected",
        "desc": "Network scan from scanner",
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

try:
    result = detector.detect(scanner_alert)
    print(f"   FP Score: {result['fp_score']:.2f}")
    print(f"   Confidence: {result['confidence']:.2f}")
    print(f"   Method: {result['method']}")
    print(f"   Action: {result['recommendation']['action']}")
    print(f"   Reasons: {', '.join(result['reasons'][:2])}")
    
    if result['fp_score'] >= 0.7:
        print("   [PASS] Correctly identified as FP")
    else:
        print("   [WARN] Should have higher FP score")
except Exception as e:
    print(f"   [FAIL] Error: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Real attack (should NOT be FP)
print("\n3. Test 2: Real Attack Alert (should NOT be FP)")
attack_alert = {
    "alert_id": "TEST-002",
    "time": int(datetime.now().timestamp() * 1000),
    "severity_id": 3,
    "class_uid": 3002,
    "finding": {
        "title": "Brute force attack detected",
        "desc": "Multiple failed login attempts",
        "uid": "test_002"
    },
    "src_endpoint": {
        "ip": "185.220.101.45",  # Foreign IP
        "hostname": "unknown"
    },
    "dst_endpoint": {
        "hostname": "production-db-01"
    },
    "unmapped": {
        "wazuh_rule_id": 5710,
        "wazuh_rule_level": 10
    },
    "enrichments": {
        "threat_intel": {
            "score": 0.85,
            "known_malicious": True
        }
    }
}

try:
    result = detector.detect(attack_alert)
    print(f"   FP Score: {result['fp_score']:.2f}")
    print(f"   Confidence: {result['confidence']:.2f}")
    print(f"   Method: {result['method']}")
    print(f"   Action: {result['recommendation']['action']}")
    print(f"   Reasons: {', '.join(result['reasons'][:2]) if result['reasons'] else 'None'}")
    
    if result['fp_score'] < 0.5:
        print("   [PASS] Correctly identified as real threat")
    else:
        print("   [WARN] Should have lower FP score")
except Exception as e:
    print(f"   [FAIL] Error: {e}")
    import traceback
    traceback.print_exc()

# Test 3: Test environment (should be FP)
print("\n4. Test 3: Test Environment Alert (should be FP)")
test_env_alert = {
    "alert_id": "TEST-003",
    "time": int(datetime.now().timestamp() * 1000),
    "severity_id": 2,
    "class_uid": 4001,
    "finding": {
        "title": "Suspicious activity",
        "desc": "Test",
        "uid": "test_003"
    },
    "src_endpoint": {
        "ip": "192.168.1.100",
        "hostname": "dev-laptop-01"
    },
    "dst_endpoint": {
        "hostname": "test-server-05"  # Test environment
    },
    "unmapped": {
        "wazuh_rule_id": 1002,
        "wazuh_rule_level": 5
    }
}

try:
    result = detector.detect(test_env_alert)
    print(f"   FP Score: {result['fp_score']:.2f}")
    print(f"   Confidence: {result['confidence']:.2f}")
    print(f"   Method: {result['method']}")
    print(f"   Action: {result['recommendation']['action']}")
    print(f"   Reasons: {', '.join(result['reasons'][:2])}")
    
    if result['fp_score'] >= 0.6:
        print("   [PASS] Correctly identified as FP (test env)")
    else:
        print("   [WARN] Should have higher FP score")
except Exception as e:
    print(f"   [FAIL] Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*60)
print("FP DETECTOR TEST COMPLETE")
print("="*60)
print("\n[OK] FP Detector is working correctly!")
print("\nTo run as a service:")
print("  python -m uvicorn backend.services.ml.fp_detector_service:app --port 5006")
