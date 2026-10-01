"""
Quick Test - FP Detector

Simple sanity check for FP detector functionality
"""

from datetime import datetime
from pymongo import MongoClient
from backend.services.ml.fp_detector import FalsePositiveDetector

print("="*60)
print("FALSE POSITIVE DETECTOR - QUICK TEST")
print("="*60)

# Initialize
db = MongoClient()['soar_db']
detector = FalsePositiveDetector(db_client=db)

# Test alert: Scanner
alert = {
    "alert_id": "quick_test_001",
    "time": int(datetime.now().timestamp() * 1000),
    "severity_id": 2,
    "class_uid": 4001,
    "finding": {
        "title": "Network scan from nessus scanner",
        "desc": "Port scan detected",
        "uid": "test_001"
    },
    "src_endpoint": {
        "hostname": "nessus-scanner"
    },
    "dst_endpoint": {
        "hostname": "web-server-01"
    },
    "unmapped": {
        "wazuh_rule_id": 40111,
        "wazuh_rule_level": 7
    }
}

print("\n📋 Testing Scanner Alert...")
result = detector.detect(alert)

print(f"\n✅ Detection Complete!")
print(f"  FP Score: {result['fp_score']:.2f}")
print(f"  Confidence: {result['confidence']:.2f}")
print(f"  Method: {result['method']}")
print(f"  Recommendation: {result['recommendation']['action']}")

print(f"\n💡 Reasons:")
for reason in result['reasons']:
    print(f"  - {reason}")

if result['fp_score'] >= 0.7:
    print("\n🎉 SUCCESS - Scanner correctly identified as FP!")
else:
    print(f"\n⚠️  Unexpected FP score: {result['fp_score']:.2f}")

print("\n" + "="*60)
print("FP Detector is working!")
print("="*60)
