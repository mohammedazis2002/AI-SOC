#!/usr/bin/env python3
"""
Test Wazuh Mapper with Local Example
"""
import sys
import json
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from services.ingestion.wazuh_mapper import WazuhToULFMapper


def main():
    print("=" * 70)
    print("Testing Wazuh Mapper")
    print("=" * 70)
    
    # Load example Wazuh alert
    example_file = Path("backend/examples/wazuh_alert_example.json")
    
    if not example_file.exists():
        print(f"❌ Example file not found: {example_file}")
        print("\nPlease create a Wazuh alert example at:")
        print(f"  {example_file}")
        return 1
    
    with open(example_file, "r") as f:
        wazuh_alert = json.load(f)
    
    print(f"\n📥 Loaded example from: {example_file}")
    print(f"   Alert ID: {wazuh_alert.get('id', 'N/A')}")
    print(f"   Rule Level: {wazuh_alert.get('rule', {}).get('level', 'N/A')}")
    
    # Map to ULF
    try:
        mapper = WazuhToULFMapper()
        ulf, warnings, summary = mapper.map_alert(wazuh_alert)
        
        print("\n✅ MAPPING SUCCESSFUL")
        print("=" * 70)
        
        print(f"\n📊 ULF Alert:")
        print(f"   Alert ID: {ulf.alert_id}")
        print(f"   Severity: {ulf.severity} ({ulf.severity_id})")
        print(f"   Finding: {ulf.finding.title}")
        print(f"   Source: {ulf.siem_source}")
        print(f"   Status: {ulf.status}")
        
        if ulf.src_endpoint:
            print(f"\n🌐 Source Endpoint:")
            print(f"   IP: {ulf.src_endpoint.ip}")
            print(f"   Port: {ulf.src_endpoint.port}")
        
        if ulf.dst_endpoint:
            print(f"\n🎯 Destination Endpoint:")
            print(f"   IP: {ulf.dst_endpoint.ip}")
            print(f"   Hostname: {ulf.dst_endpoint.hostname}")
        
        if ulf.observables:
            print(f"\n🔍 Observables ({len(ulf.observables)}):")
            for obs in ulf.observables[:3]:  # Show first 3
                print(f"   - {obs.type}: {obs.value}")
        
        if warnings:
            print(f"\n⚠️  Validation Warnings:")
            for warning in warnings:
                print(f"   - {warning}")
        
        print(f"\n📋 Validation Summary:")
        print(f"   OCSF Compliant: {summary['validation_passed']}")
        print(f"   Has Finding: {summary['checks']['data_quality']['has_finding']}")
        print(f"   Has Metadata: {summary['checks']['data_quality']['has_metadata']}")
        
        # Save output
        output_file = Path("test_wazuh_mapper_output.json")
        with open(output_file, "w") as f:
            json.dump(ulf.model_dump(mode='json'), f, indent=2, default=str)
        
        print(f"\n💾 Full ULF output saved to: {output_file}")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ MAPPING FAILED")
        print(f"   Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
