#!/usr/bin/env python3
"""
Test OCSF Schema Loader and Event Classifier

Verifies that:
1. Schema loads correctly from local OCSF repository
2. Event classifier correctly identifies class/category
3. Different event types get different class_uids
"""
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from services.ocsf.schema_loader import schema_loader
from services.classification.event_classifier import event_classifier


def test_schema_loader():
    """Test OCSF schema loading"""
    print("=" * 70)
    print("Testing OCSF Schema Loader")
    print("=" * 70)
    
    # Load schema
    schema_loader.load_schema()
    
    # Check version
    version = schema_loader.get_schema_version()
    print(f"\n📋 OCSF Schema Version: {version}")
    
    # List categories
    print("\n📁 Categories:")
    for cat in schema_loader.list_categories():
        print(f"   {cat['uid']:2d}: {cat['name']} - {cat['caption']}")
    
    # List some event classes
    print("\n📄 Event Classes (sample):")
    classes = schema_loader.list_classes()
    for cls in classes[:15]:
        print(f"   {cls['class_uid']:5d}: {cls['name']:30s} ({cls['category']})")
    
    print(f"\n   ... and {len(classes) - 15} more classes")
    
    # Test keyword search
    print("\n🔍 Keyword Search Tests:")
    
    test_keywords = [
        ['authentication'],
        ['firewall'],
        ['malware'],
        ['file'],
        ['dns'],
    ]
    
    for keywords in test_keywords:
        matches = schema_loader.search_by_keywords(keywords)
        if matches:
            best = matches[0]
            print(f"   '{keywords[0]}' → {best['class_uid']} ({best['class_name']}) score={best['score']}")
        else:
            print(f"   '{keywords[0]}' → No matches")
    
    print("\n✅ Schema Loader Test Complete")
    return True


def test_event_classifier():
    """Test event classification"""
    print("\n" + "=" * 70)
    print("Testing Event Classifier")
    print("=" * 70)
    
    # Test cases with expected results
    test_cases = [
        {
            "name": "SSH Failed Login",
            "log": "Jan 15 14:23:45 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2",
            "expected_class_uid": 3002,
            "expected_category": "iam"
        },
        {
            "name": "Firewall Block",
            "log": "2024-01-15T14:23:45Z FIREWALL: DENY TCP 10.0.0.50:45678 -> 172.16.0.10:443",
            "expected_class_uid": 4001,
            "expected_category": "network"
        },
        {
            "name": "Malware Detection",
            "log": "ALERT: Trojan.GenericKD.12345 detected in C:\\Users\\john\\Downloads\\setup.exe - QUARANTINED",
            "expected_class_uid": 2001,
            "expected_category": "findings"
        },
        {
            "name": "File Access",
            "log": "User 'admin' accessed sensitive file /etc/shadow from IP 10.0.0.5 at 2024-01-15 14:30:00",
            "expected_class_uid": 1001,
            "expected_category": "system"
        },
        {
            "name": "DNS Query",
            "log": "DNS query for malicious-domain.com from 192.168.1.50 - blocked",
            "expected_class_uid": 4003,
            "expected_category": "network"
        },
        {
            "name": "Process Execution",
            "log": "Process started: pid=1234 cmd='powershell.exe -enc base64data' user=SYSTEM",
            "expected_class_uid": 1007,
            "expected_category": "system"
        },
        {
            "name": "Account Created",
            "log": "New user account created: username=backdoor, uid=1001, by admin",
            "expected_class_uid": 3001,
            "expected_category": "iam"
        },
    ]
    
    results = []
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n{'─' * 70}")
        print(f"Test {i}/{len(test_cases)}: {test['name']}")
        print(f"{'─' * 70}")
        print(f"Log: {test['log'][:60]}...")
        
        # Classify
        result = event_classifier.classify({"message": test['log']})
        
        # Check results
        class_match = result.class_uid == test['expected_class_uid']
        category_match = result.category == test['expected_category']
        success = class_match and category_match
        
        status = "✅" if success else "❌"
        
        print(f"\n{status} Classification Result:")
        print(f"   Class UID:  {result.class_uid} (expected: {test['expected_class_uid']})")
        print(f"   Class Name: {result.class_name}")
        print(f"   Caption:    {result.caption}")
        print(f"   Category:   {result.category} (expected: {test['expected_category']})")
        print(f"   Confidence: {result.confidence:.2f}")
        print(f"   Method:     {result.method}")
        
        if result.matched_pattern:
            print(f"   Pattern:    {result.matched_pattern}")
        if result.matched_keywords:
            print(f"   Keywords:   {result.matched_keywords}")
        
        results.append({
            "name": test['name'],
            "success": success,
            "class_uid": result.class_uid,
            "expected_class_uid": test['expected_class_uid'],
        })
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in results if r['success'])
    print(f"\n✅ Passed: {passed}/{len(results)}")
    
    for r in results:
        status = "✅" if r['success'] else "❌"
        print(f"{status} {r['name']}: class_uid={r['class_uid']}")
    
    return passed == len(results)


def main():
    print("\n🚀 OCSF Classification System Test\n")
    
    try:
        schema_ok = test_schema_loader()
        classifier_ok = test_event_classifier()
        
        print("\n" + "=" * 70)
        if schema_ok and classifier_ok:
            print("✅ ALL TESTS PASSED!")
            return 0
        else:
            print("❌ SOME TESTS FAILED")
            return 1
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
