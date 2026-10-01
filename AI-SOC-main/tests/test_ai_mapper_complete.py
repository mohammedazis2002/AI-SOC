#!/usr/bin/env python3
"""
Complete AI Mapper test script
Tests connection, model availability, and log mapping
"""
import asyncio
import httpx
import json
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from services.ingestion.ai_mapper import AIMapper

# Test configurations
TEST_LOGS = [
    {
        "name": "SSH Brute Force",
        "log": "Jan 15 14:23:45 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2",
        "expected_severity": "High",
    },
    {
        "name": "Firewall Block",
        "log": "2024-01-15T14:23:45Z FIREWALL: DENY TCP 10.0.0.50:45678 -> 172.16.0.10:443",
        "expected_severity": "Medium",
    },
    {
        "name": "Malware Detection",
        "log": "ALERT: Trojan.GenericKD.12345 detected in C:\\Users\\john\\Downloads\\setup.exe - QUARANTINED",
        "expected_severity": "Critical",
    },
    {
        "name": "Unstructured Log",
        "log": "something happened at some time maybe check it out",
        "expected_severity": "Unknown",
    }
]


async def test_connection(llm_url: str):
    """Test basic connectivity to LLM service"""
    print("\n" + "="*70)
    print("STEP 1: Testing LLM Service Connection")
    print("="*70)
    
    base_url = llm_url.replace("/v1/chat/completions", "")
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Test models endpoint
        try:
            print(f"\n🔍 Testing: {base_url}/v1/models")
            response = await client.get(f"{base_url}/v1/models")
            
            if response.status_code == 200:
                models = response.json()
                print(f"✅ Connected! Available models:")
                for model in models.get("data", []):
                    print(f"   - {model.get('id', 'unknown')}")
                return True
            else:
                print(f"❌ HTTP {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False


async def test_simple_completion(llm_url: str, model_name: str):
    """Test a simple LLM completion"""
    print("\n" + "="*70)
    print("STEP 2: Testing Simple LLM Completion")
    print("="*70)
    
    payload = {
        "model": model_name,
        "messages": [
            {"role": "user", "content": "Respond with just the word 'working' if you can read this."}
        ],
        "temperature": 0.1,
        "max_tokens": 10
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            print(f"\n🔍 Sending test prompt to {model_name}...")
            response = await client.post(llm_url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            
            print(f"✅ LLM Response: '{content}'")
            return True
            
    except httpx.ReadTimeout:
        print(f"❌ Timeout! Model is too slow or server is overloaded")
        print("   Try: 1) Use a smaller/faster model")
        print("        2) Increase timeout")
        print("        3) Check server resources")
        return False
        
    except Exception as e:
        print(f"❌ Completion failed: {e}")
        return False


async def test_ai_mapper():
    """Test the AI Mapper with real log samples"""
    print("\n" + "="*70)
    print("STEP 3: Testing AI Mapper with Sample Logs")
    print("="*70)
    
    # Initialize mapper
    mapper = AIMapper()
    
    # Health check first
    print("\n🏥 Running health check...")
    health = await mapper.health_check()
    print(f"   Status: {health.get('status')}")
    print(f"   URL: {health.get('llm_url')}")
    print(f"   Model: {health.get('model_name')}")
    
    if health.get('status') != 'healthy':
        print(f"\n❌ Health check failed: {health.get('error')}")
        return False
    
    print("\n✅ Health check passed!\n")
    
    # Test each log
    results = []
    for i, test_case in enumerate(TEST_LOGS, 1):
        print(f"\n{'─'*70}")
        print(f"Test {i}/{len(TEST_LOGS)}: {test_case['name']}")
        print(f"{'─'*70}")
        print(f"Raw Log: {test_case['log'][:100]}...")
        
        try:
            # Map the log
            mapped_data, needs_review = await mapper.map_log_event(test_case['log'])
            
            # Display results
            print(f"\n📊 Results:")
            print(f"   Finding: {mapped_data.get('finding')}")
            print(f"   Severity: {mapped_data.get('severity')}")
            print(f"   Confidence: {mapped_data.get('confidence', 0):.2f}")
            print(f"   Category: {mapped_data.get('event_category')}")
            
            if mapped_data.get('source_ip'):
                print(f"   Source IP: {mapped_data['source_ip']}")
            if mapped_data.get('destination_ip'):
                print(f"   Dest IP: {mapped_data['destination_ip']}")
            if mapped_data.get('username'):
                print(f"   Username: {mapped_data['username']}")
            
            print(f"\n   Needs Review: {'YES ⚠️' if needs_review else 'NO ✓'}")
            if needs_review:
                print(f"   Reason: {mapped_data.get('review_reason', 'Unknown')}")
            
            print(f"\n   Recommended Action: {mapped_data.get('recommended_action')}")
            print(f"   Reasoning: {mapped_data.get('reasoning', 'N/A')[:100]}...")
            
            results.append({
                "name": test_case['name'],
                "success": True,
                "confidence": mapped_data.get('confidence', 0),
                "needs_review": needs_review
            })
            
        except Exception as e:
            print(f"\n❌ Mapping failed: {e}")
            results.append({
                "name": test_case['name'],
                "success": False,
                "error": str(e)
            })
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    successful = sum(1 for r in results if r.get('success'))
    print(f"\nTests passed: {successful}/{len(results)}")
    
    for result in results:
        status = "✅" if result.get('success') else "❌"
        print(f"{status} {result['name']}")
        if result.get('success'):
            print(f"   Confidence: {result.get('confidence', 0):.2f} | Review: {result.get('needs_review')}")
    
    return successful == len(results)


async def main():
    """Run all tests"""
    
    print("="*70)
    print("AI MAPPER COMPLETE TEST SUITE")
    print("="*70)
    
    # Configuration
    llm_url = "http://ollama:11434/v1/chat/completions"
    model_name = "mistral:latest"
    
    print(f"\nConfiguration:")
    print(f"  LLM URL: {llm_url}")
    print(f"  Model: {model_name}")
    
    # Run tests in sequence
    try:
        # Test 1: Connection
        if not await test_connection(llm_url):
            print("\n❌ Connection test failed. Check if Ollama is running:")
            print("   docker-compose ps")
            print("   docker-compose logs ollama")
            return 1
        
        # Test 2: Simple completion
        if not await test_simple_completion(llm_url, model_name):
            print(f"\n❌ Model '{model_name}' is not working properly")
            print(f"   Try pulling it: docker-compose exec ollama ollama pull {model_name}")
            return 1
        
        # Test 3: Full AI mapper
        if not await test_ai_mapper():
            print("\n❌ AI Mapper tests failed")
            return 1
        
        print("\n" + "="*70)
        print("🎉 ALL TESTS PASSED!")
        print("="*70)
        print("\nYour AI Mapper is working correctly!")
        print("You can now integrate it into your SIEM alert processing pipeline.")
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)