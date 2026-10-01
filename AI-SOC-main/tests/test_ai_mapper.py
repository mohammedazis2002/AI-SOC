#!/usr/bin/env python3
"""
Test AI Mapper with Sample Logs
Requires Ollama to be running with mistral model
"""
import asyncio
import sys
import json
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from services.ingestion.ai_mapper import AIMapper


# Sample logs to test
TEST_LOGS = [
    {
        "name": "SSH Brute Force",
        "log": "Jan 15 14:23:45 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2"
    },
    {
        "name": "Firewall Block",
        "log": "2024-01-15T14:23:45Z FIREWALL: DENY TCP 10.0.0.50:45678 -> 172.16.0.10:443"
    },
    {
        "name": "Malware Detection",
        "log": "ALERT: Trojan.GenericKD.12345 detected in C:\\Users\\john\\Downloads\\setup.exe - QUARANTINED"
    },
    {
        "name": "Custom Log",
        "log": "User 'admin' accessed sensitive file /etc/shadow from IP 10.0.0.5 at 2024-01-15 14:30:00"
    }
]


async def test_ai_mapper():
    print("=" * 70)
    print("Testing AI Mapper")
    print("=" * 70)
    
    # Initialize AI mapper
    mapper = AIMapper()
    
    # Health check
    print("\n🏥 Checking LLM service health...")
    health = await mapper.health_check()
    
    if health.get("status") != "healthy":
        print(f"❌ LLM service is not healthy: {health.get('error')}")
        print("\nMake sure Ollama is running:")
        print("  docker-compose ps ollama")
        print("  docker-compose logs ollama")
        return 1
    
    print(f"✅ LLM service healthy")
    print(f"   URL: {health.get('llm_url')}")
    print(f"   Model: {health.get('model_name')}")
    
    # Test each log
    results = []
    full_ulfs = []  # Store full ULF objects
    
    for i, test_case in enumerate(TEST_LOGS, 1):
        print(f"\n{'─' * 70}")
        print(f"Test {i}/{len(TEST_LOGS)}: {test_case['name']}")
        print(f"{'─' * 70}")
        print(f"Raw Log: {test_case['log'][:80]}...")
        
        try:
            # Map to ULF using AI
            ulf, confidence = await mapper.map_to_ulf(test_case['log'], source="custom")
            
            print(f"\n✅ AI Mapping Successful")
            print(f"   Alert ID: {ulf.alert_id}")
            print(f"   Finding: {ulf.finding.title}")
            print(f"   Severity: {ulf.severity} ({ulf.severity_id})")
            print(f"   Confidence: {confidence:.2f}")
            
            if ulf.src_endpoint:
                print(f"   Source IP: {ulf.src_endpoint.ip}")
                if ulf.src_endpoint.port:
                    print(f"   Source Port: {ulf.src_endpoint.port}")
            if ulf.dst_endpoint:
                print(f"   Dest IP: {ulf.dst_endpoint.ip}")
                if ulf.dst_endpoint.port:
                    print(f"   Dest Port: {ulf.dst_endpoint.port}")
            if ulf.actor:
                print(f"   Username: {ulf.actor.name}")
            if ulf.process:
                print(f"   Process: {ulf.process.name}")
            if ulf.file:
                print(f"   File: {ulf.file.path or ulf.file.name}")
            
            # Check unmapped AI data
            ai_data = ulf.unmapped
            print(f"\n📊 AI Analysis:")
            print(f"   Attack Type: {ai_data.get('ai_attack_type')}")
            print(f"   Category: {ai_data.get('ai_event_category')}")
            if ulf.finding.types:
                print(f"   MITRE Techniques: {', '.join(ulf.finding.types)}")
            print(f"   Needs Review: {ai_data.get('ai_needs_review')}")
            print(f"   Recommended Action: {ai_data.get('ai_recommended_action')}")
            
            # Store full ULF
            full_ulfs.append({
                "test_name": test_case['name'],
                "ulf": ulf.model_dump(mode='json')
            })
            
            results.append({
                "name": test_case['name'],
                "success": True,
                "confidence": confidence,
                "alert_id": ulf.alert_id,
                "severity": ulf.severity
            })
            
        except Exception as e:
            print(f"\n❌ Mapping failed: {e}")
            import traceback
            traceback.print_exc()
            results.append({
                "name": test_case['name'],
                "success": False,
                "error": str(e)
            })
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    successful = sum(1 for r in results if r.get('success'))
    print(f"\nTests passed: {successful}/{len(results)}")
    
    for result in results:
        status = "✅" if result.get('success') else "❌"
        print(f"{status} {result['name']}")
        if result.get('success'):
            print(f"   Confidence: {result.get('confidence', 0):.2f} | Severity: {result.get('severity')}")
    
    # Save results
    output_file = Path("test_ai_mapper_output.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: {output_file}")
    
    # Save full OCSF ULF objects
    ulf_output_file = Path("test_ai_mapper_ulf_full.json")
    with open(ulf_output_file, "w") as f:
        json.dump(full_ulfs, f, indent=2, default=str)
    
    print(f"💾 Full OCSF ULF objects saved to: {ulf_output_file}")
    print(f"\n   Compare with Wazuh mapper output:")
    print(f"   - AI Mapper:    {ulf_output_file}")
    print(f"   - Wazuh Mapper: test_wazuh_mapper_output.json")
    
    return 0 if successful == len(results) else 1


def main():
    return asyncio.run(test_ai_mapper())


if __name__ == "__main__":
    exit(main())
