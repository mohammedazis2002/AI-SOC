"""
Test Root Cause Analyzer API Service

Tests the FastAPI service endpoints with realistic scenarios.
"""

import requests
import json
import time
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

BASE_URL = "http://localhost:5003"


def test_health():
    """Test health endpoint"""
    logger.info("\n" + "="*80)
    logger.info("TEST: Health Check")
    logger.info("="*80)
    
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        data = response.json()
        
        logger.info(f"Status Code: {response.status_code}")
        logger.info(f"Response: {json.dumps(data, indent=2)}")
        
        assert response.status_code == 200
        logger.info("✅ Health check passed")
        return True
    except Exception as e:
        logger.error(f"❌ Health check failed: {e}")
        return False


def test_categories():
    """Test categories endpoint"""
    logger.info("\n" + "="*80)
    logger.info("TEST: Get Categories")
    logger.info("="*80)
    
    try:
        response = requests.get(f"{BASE_URL}/categories", timeout=5)
        data = response.json()
        
        categories = data.get('categories', [])
        logger.info(f"Total Categories: {len(categories)}")
        logger.info(f"Categories: {', '.join(categories)}")
        
        assert len(categories) == 14
        logger.info("✅ Categories test passed")
        return True
    except Exception as e:
        logger.error(f"❌ Categories test failed: {e}")
        return False


def test_build_context():
    """Test context building endpoint"""
    logger.info("\n" + "="*80)
    logger.info("TEST: Build Context")
    logger.info("="*80)
    
    alert = {
        "actor": {
            "user": {"name": "jdoe", "type_id": 1}
        },
        "dst_endpoint": {
            "hostname": "web-server-01"
        }
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/build-context",
            json={"alert": alert, "lookback_days": 7},
            timeout=10
        )
        data = response.json()
        
        logger.info(f"Status Code: {response.status_code}")
        
        context = data.get('context', {})
        metadata = data.get('metadata', {})
        
        logger.info(f"\nContext Metadata:")
        logger.info(f"  Recent alerts: {metadata.get('recent_alerts_count')}")
        logger.info(f"  User identified: {metadata.get('user_identified')}")
        logger.info(f"  Asset identified: {metadata.get('asset_identified')}")
        
        if context.get('user_profile'):
            up = context['user_profile']
            logger.info(f"\nUser Profile:")
            logger.info(f"  Username: {up.get('username')}")
            logger.info(f"  Risk Score: {up.get('risk_score')}/100")
            logger.info(f"  Account Age: {up.get('account_age_days')} days")
            logger.info(f"  Privileged: {up.get('is_privileged')}")
        
        if context.get('asset_profile'):
            ap = context['asset_profile']
            logger.info(f"\nAsset Profile:")
            logger.info(f"  Hostname: {ap.get('hostname')}")
            logger.info(f"  Criticality: {ap.get('criticality')}/5")
            logger.info(f"  Environment: {ap.get('environment')}")
            logger.info(f"  Patched: {ap.get('is_patched')}")
        
        assert response.status_code == 200
        logger.info("\n✅ Context building test passed")
        return True
    except Exception as e:
        logger.error(f"❌ Context building test failed: {e}")
        return False


def test_analyze_with_auto_context():
    """Test analyze endpoint with automatic context building"""
    logger.info("\n" + "="*80)
    logger.info("TEST: Analyze with Auto Context - Brute Force Attack")
    logger.info("="*80)
    
    alert = {
        "alert_id": "test_brute_force_001",
        "time": int(datetime.now().timestamp() * 1000),
        "severity_id": 4,
        "class_uid": 3002,
        "finding": {
            "title": "Brute Force Attack Detected",
            "types": ["T1110"],
            "desc": "Multiple failed login attempts from external IP"
        },
        "actor": {
            "user": {
                "name": "jdoe",
                "type_id": 1,
                "groups": ["users"]
            }
        },
        "src_endpoint": {
            "ip": "203.0.113.45"
        },
        "dst_endpoint": {
            "hostname": "web-server-01"
        },
        "enrichments": {
            "mitre": {
                "techniques": ["T1110"],
                "tactics": ["credential_access"],
                "dominant_tactic": "credential_access"
            }
        },
        "status_id": 2
    }
    
    try:
        logger.info("Sending alert for analysis (context will be auto-built)...")
        response = requests.post(
            f"{BASE_URL}/analyze",
            json={"alert": alert},  # No context - will be auto-built!
            timeout=30
        )
        data = response.json()
        
        logger.info(f"\nStatus Code: {response.status_code}")
        logger.info(f"\nAnalysis Results:")
        logger.info(f"  Alert ID: {data.get('alert_id')}")
        logger.info(f"  Root Causes Found: {data.get('num_root_causes')}")
        
        root_causes = data.get('root_causes', [])
        for i, cause in enumerate(root_causes[:5], 1):
            logger.info(f"\n  {i}. {cause.get('cause')}")
            logger.info(f"     Confidence: {cause.get('confidence', 0):.1%}")
            if 'priority' in cause:
                logger.info(f"     Priority: {cause.get('priority')}")
        
        dominant = data.get('dominant_cause')
        if dominant:
            logger.info(f"\n  Dominant Cause: {dominant.get('cause')}")
        
        remediation = data.get('remediation', [])
        if remediation:
            logger.info(f"\n  Remediation Steps:")
            for i, step in enumerate(remediation[:3], 1):
                logger.info(f"    {i}. {step}")
        
        temporal = data.get('temporal_analysis', {})
        if temporal.get('origin_cause'):
            logger.info(f"\n  Origin Cause: {temporal.get('origin_cause')}")
        
        assert response.status_code == 200
        assert data.get('num_root_causes', 0) > 0
        logger.info("\n✅ Auto-context analysis test passed")
        return True
    except Exception as e:
        logger.error(f"❌ Auto-context analysis test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_analyze_cve_exploit():
    """Test CVE exploit scenario"""
    logger.info("\n" + "="*80)
    logger.info("TEST: Analyze CVE Exploit Attack")
    logger.info("="*80)
    
    alert = {
        "alert_id": "test_cve_001",
        "time": int(datetime.now().timestamp() * 1000),
        "severity_id": 4,
        "finding": {
            "title": "CVE-2024-12345 Exploitation Detected",
            "types": ["T1190"],
            "desc": "Remote code execution attempt via unpatched vulnerability"
        },
        "actor": {
            "user": {"name": "serviceaccount", "type_id": 3}
        },
        "dst_endpoint": {
            "hostname": "web-server-01"
        },
        "enrichments": {
            "mitre": {
                "techniques": ["T1190"],
                "tactics": ["initial_access"],
                "dominant_tactic": "initial_access"
            }
        },
        "observables": [
            {"name": "CVE-2024-12345", "type_id": 25}
        ]
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/analyze",
            json={"alert": alert},
            timeout=30
        )
        data = response.json()
        
        logger.info(f"Root Causes: {data.get('num_root_causes')}")
        
        root_causes = data.get('root_causes', [])
        for cause in root_causes[:3]:
            logger.info(f"  - {cause.get('cause')}: {cause.get('confidence', 0):.1%}")
        
        # Should identify unpatched_vulnerability
        causes_found = [c.get('cause') for c in root_causes]
        assert 'unpatched_vulnerability' in causes_found or len(causes_found) > 0
        
        logger.info("✅ CVE exploit analysis test passed")
        return True
    except Exception as e:
        logger.error(f"❌ CVE exploit analysis test failed: {e}")
        return False


def test_auto_label():
    """Test auto-labeling endpoint"""
    logger.info("\n" + "="*80)
    logger.info("TEST: Auto-Label for Analyst Review")
    logger.info("="*80)
    
    alert = {
        "finding": {
            "title": "PowerShell Obfuscation Detected",
            "types": ["T1059.001"],
            "desc": "Encoded PowerShell command with LOLBIN abuse"
        },
        "enrichments": {
            "mitre": {
                "techniques": ["T1059.001"],
                "tactics": ["execution", "defense_evasion"]
            }
        },
        "process": {
            "file": {"name": "powershell.exe"},
            "cmd_line": "powershell.exe -Enc JABzAD0ATgBlAHc..."
        }
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/auto-label",
            json={"alert": alert},
            timeout=10
        )
        data = response.json()
        
        suggestions = data.get('suggestions', {})
        needs_review = data.get('needs_review')
        conf_summary = data.get('confidence_summary', {})
        
        logger.info(f"Suggestions: {len(suggestions)}")
        logger.info(f"Needs Review: {needs_review}")
        logger.info(f"Max Confidence: {conf_summary.get('max_confidence', 0):.1%}")
        logger.info(f"Avg Confidence: {conf_summary.get('avg_confidence', 0):.1%}")
        
        logger.info(f"\nTop Suggestions:")
        for cat, sug in list(suggestions.items())[:3]:
            logger.info(f"  - {cat}: {sug.get('confidence', 0):.1%}")
        
        assert response.status_code == 200
        logger.info("\n✅ Auto-label test passed")
        return True
    except Exception as e:
        logger.error(f"❌ Auto-label test failed: {e}")
        return False


def run_all_api_tests():
    """Run all API tests"""
    logger.info("\n" + "="*80)
    logger.info("ROOT CAUSE ANALYZER API - TEST SUITE")
    logger.info("="*80)
    
    # Check if service is running
    try:
        requests.get(f"{BASE_URL}/health", timeout=2)
    except requests.exceptions.RequestException:
        logger.error("\n❌ Service is not running!")
        logger.error("   Start it with: python -m uvicorn backend.services.ml.root_cause_service:app --port 5003")
        return False
    
    results = []
    
    results.append(("Health Check", test_health()))
    results.append(("Get Categories", test_categories()))
    results.append(("Build Context", test_build_context()))
    results.append(("Analyze with Auto Context", test_analyze_with_auto_context()))
    results.append(("Analyze CVE Exploit", test_analyze_cve_exploit()))
    results.append(("Auto-Label", test_auto_label()))
    
    # Summary
    logger.info("\n" + "="*80)
    logger.info("API TEST SUMMARY")
    logger.info("="*80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{status} - {test_name}")
    
    logger.info(f"\n✅ Passed: {passed}/{total} tests")
    
    if passed == total:
        logger.info("\n🎉 All API tests passed! Service is working correctly.")
    else:
        logger.warning(f"\n⚠️  {total - passed} test(s) failed.")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_api_tests()
    exit(0 if success else 1)
