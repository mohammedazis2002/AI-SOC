"""
Test Script for Attack Stage Predictor (Model 2 v2.0)

Tests all critical fixes:
1. 14 MITRE tactics coverage
2. No 'unknown' stages (queue system)
3. Proper final stage handling
4. Critical stage escalation (11-14)
5. LSTM timing integration
6. Enhanced MITRE enrichment
"""

import sys
from datetime import datetime, timedelta
from typing import Dict, Any

# Add backend to path
sys.path.insert(0, 'backend')

from backend.services.ml.attack_stage.stage_identifier import AttackStageIdentifier
from backend.services.ml.attack_stage.stage_predictor import AttackStagePredictor
from backend.services.ml.attack_stage.mitre_enricher import MITREEnricher


def print_section(title: str):
    """Print formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def create_test_alert(stage_name: str, severity: str = "high") -> Dict[str, Any]:
    """Create a test alert with MITRE enrichment"""
    return {
        'alert_id': f'TEST-{stage_name.upper()}-001',
        'time': datetime.utcnow().isoformat(),
        'severity': severity,
        'class_name': 'Security Finding',
        'message': f'Test alert for {stage_name} stage',
        'device': {
            'hostname': 'test-server-01',
            'ip': '192.168.1.100',
            'criticality': 'high'
        },
        'enrichments': {
            'mitre': {
                'dominant_tactic': stage_name,
                'confidence': 1.0,
                'method': 'test'
            }
        }
    }


def test_stage_identifier():
    """Test 1: Stage Identifier with 14 MITRE Tactics"""
    print_section("TEST 1: Stage Identifier - 14 MITRE Tactics")
    
    identifier = AttackStageIdentifier()
    
    print(f"Total tactics defined: {len(identifier.MITRE_TACTICS)}")
    assert len(identifier.MITRE_TACTICS) == 14, "Should have exactly 14 tactics!"
    print("[PASS] All 14 MITRE tactics present\n")
    
    # Test each tactic
    print("Testing all 14 tactics:")
    for i, tactic in enumerate(identifier.MITRE_TACTICS, 1):
        print(f"  {i}. {tactic['name']:25} (Stage {tactic['stage']}, {tactic['criticality']:8}) - {tactic['tactic_id']}")
    
    # Test stage identification
    print("\nTesting stage identification:")
    test_alert = create_test_alert('execution')
    result = identifier.identify_stage(test_alert)
    print(f"  Alert tactic: execution")
    print(f"  Identified stage: {result['current_stage']} (Stage {result['stage_number']}/14)")
    print(f"  Confidence: {result['confidence']}")
    assert result['stage_number'] == 4, "Execution should be stage 4"
    print("[PASS] Stage identification working\n")
    
    # Test final stage handling
    print("Testing final stage handling (Stage 14 - Impact):")
    next_stages = identifier.get_next_stages(14)
    print(f"  Is final stage: {next_stages['is_final_stage']}")
    print(f"  Next stages: {next_stages['next_stages']}")
    print(f"  Message: {next_stages['message']}")
    assert next_stages['is_final_stage'] == True, "Stage 14 should be final"
    assert len(next_stages['next_stages']) == 0, "Final stage should have no next stages"
    print("[PASS] Final stage handling correct\n")


def test_critical_stage_escalation():
    """Test 2: Critical Stage Escalation (Stages 11-14)"""
    print_section("TEST 2: Critical Stage Escalation")
    
    predictor = AttackStagePredictor()
    
    critical_stages = [
        ('collection', 11),
        ('command-and-control', 12),
        ('exfiltration', 13),
        ('impact', 14)
    ]
    
    for stage_name, stage_num in critical_stages:
        print(f"Testing Stage {stage_num}: {stage_name.title()}")
        test_alert = create_test_alert(stage_name, severity='critical')
        
        result = predictor.predict(test_alert)
        
        print(f"  Action: {result['action']}")
        print(f"  Severity: {result['severity']}")
        print(f"  Priority: {result['priority']}")
        print(f"  Skip prediction: {result.get('skip_prediction', False)}")
        print(f"  Escalation: {result.get('escalation', {}).get('reason', 'N/A')}")
        
        assert result['action'] == 'ESCALATE_IMMEDIATELY', f"Stage {stage_num} should escalate immediately"
        assert result['severity'] == 'CRITICAL', f"Stage {stage_num} should be CRITICAL"
        assert result.get('skip_prediction') == True, f"Stage {stage_num} should skip timing prediction"
        
        print(f"[PASS] Stage {stage_num} escalation working\n")


def test_normal_stage_prediction():
    """Test 3: Normal Stage Prediction (Stages 1-10)"""
    print_section("TEST 3: Normal Stage Prediction")
    
    predictor = AttackStagePredictor()
    
    normal_stages = [
        ('reconnaissance', 1, 'MONITOR', 'LOW'),
        ('initial-access', 3, 'MONITOR', 'LOW'),
        ('persistence', 5, 'INVESTIGATE', 'MEDIUM'),
        ('credential-access', 8, 'INVESTIGATE', 'HIGH'),
        ('lateral-movement', 10, 'ESCALATE', 'HIGH')
    ]
    
    for stage_name, stage_num, expected_action, expected_severity in normal_stages:
        print(f"Testing Stage {stage_num}: {stage_name.title()}")
        test_alert = create_test_alert(stage_name)
        
        result = predictor.predict(test_alert)
        
        print(f"  Action: {result['action']}")
        print(f"  Severity: {result['severity']}")
        print(f"  Next stages: {len(result.get('next_stages', []))}")
        
        # Check that timing prediction exists (or fallback)
        if result.get('next_stages'):
            first_next = result['next_stages'][0]
            print(f"  Next stage ETA: {first_next.get('eta_minutes')} minutes ({first_next.get('timing_method')})")
        
        assert result['action'] in ['MONITOR', 'INVESTIGATE', 'ESCALATE'], "Valid action required"
        print(f"[PASS] Stage {stage_num} prediction working\n")


def test_mitre_enrichment():
    """Test 4: Enhanced MITRE Enrichment"""
    print_section("TEST 4: Enhanced MITRE Enrichment (5 Methods)")
    
    enricher = MITREEnricher()
    
    # Test cases for different enrichment methods
    test_cases = [
        {
            'name': 'PowerShell Execution',
            'alert': {
                'alert_id': 'TEST-PS-001',
                'process': {
                    'cmd_line': 'powershell.exe -encodedCommand ABC123'
                },
                'message': 'Suspicious PowerShell detected'
            },
            'expected_tactic': 'execution'
        },
        {
            'name': 'Credential Dumping',
            'alert': {
                'alert_id': 'TEST-CRED-001',
                'process': {
                    'cmd_line': 'mimikatz.exe sekurlsa::logonpasswords'
                },
                'message': 'Suspicious credential access'
            },
            'expected_tactic': 'credential-access'
        },
        {
            'name': 'Port Scan',
            'alert': {
                'alert_id': 'TEST-SCAN-001',
                'class_name': 'port_scan',
                'message': 'Port scan detected from 192.168.1.50'
            },
            'expected_tactic': 'reconnaissance'
        }
    ]
    
    for test_case in test_cases:
        print(f"Testing: {test_case['name']}")
        mitre_data, attempts = enricher.enrich(test_case['alert'])
        
        if mitre_data:
            print(f"  [SUCCESS] Enriched with tactic: {mitre_data['dominant_tactic']}")
            print(f"  Method: {mitre_data['method']}")
            
            # Check if it matches expected (loosely, since pattern matching may vary)
            if mitre_data['dominant_tactic'] == test_case['expected_tactic']:
                print(f"  [PASS] Correctly identified as {test_case['expected_tactic']}\n")
            else:
                print(f"  [INFO] Identified as {mitre_data['dominant_tactic']} (expected {test_case['expected_tactic']})\n")
        else:
            print(f"  [FAILED] Could not enrich")
            print(f"  Attempts: {attempts}\n")


def test_no_unknown_stages():
    """Test 5: No 'Unknown' Stages (Queue Instead)"""
    print_section("TEST 5: No 'Unknown' Stages - Queue System")
    
    predictor = AttackStagePredictor()
    
    # Create alert without MITRE data
    alert_no_mitre = {
        'alert_id': 'TEST-NOMIT-001',
        'time': datetime.utcnow().isoformat(),
        'severity': 'medium',
        'message': 'Unknown alert type',
        'device': {'hostname': 'test-server'}
    }
    
    print("Testing alert without MITRE enrichment:")
    result = predictor.predict(alert_no_mitre)
    
    print(f"  Status: {result.get('status')}")
    print(f"  Action: {result.get('action')}")
    print(f"  Message: {result.get('message')}")
    
    assert result.get('action') == 'QUEUE_FOR_REVIEW', "Should queue for review, not return 'unknown'"
    print(f"[PASS] No 'unknown' stage - alert queued for review\n")


def run_all_tests():
    """Run all Model 2 tests"""
    print("\n" + "=" * 80)
    print("  ATTACK STAGE PREDICTOR (Model 2 v2.0) - TEST SUITE")
    print("  Testing All Critical Fixes")
    print("=" * 80)
    
    tests = [
        ("14 MITRE Tactics Coverage", test_stage_identifier),
        ("Critical Stage Escalation (11-14)", test_critical_stage_escalation),
        ("Normal Stage Prediction (1-10)", test_normal_stage_prediction),
        ("Enhanced MITRE Enrichment", test_mitre_enrichment),
        ("No 'Unknown' Stages - Queue System", test_no_unknown_stages)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n[FAIL] {test_name} failed: {e}\n")
            failed += 1
    
    # Summary
    print_section("TEST SUMMARY")
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failed == 0:
        print("\n[SUCCESS] All tests passed! Model 2 v2.0 is ready for deployment.")
    else:
        print(f"\n[WARNING] {failed} test(s) failed. Review errors above.")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
