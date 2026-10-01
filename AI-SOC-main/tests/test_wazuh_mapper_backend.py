import json
import sys
from pathlib import Path

# Add the parent directory to the path so we can import from backend
sys.path.insert(0, str(Path(__file__).parent))

from services.ingestion.wazuh_mapper import WazuhToULFMapper

# Load example Wazuh alert
example_path = Path(__file__).parent / "examples" / "wazuh_alert_example.json"

print(f"Loading Wazuh alert from: {example_path}")
print(f"File exists: {example_path.exists()}")

if not example_path.exists():
    print(f"\n❌ Error: File not found at {example_path}")
    sys.exit(1)

with open(example_path, "r") as f:
    wazuh_alert = json.load(f)

print("✓ Wazuh alert loaded successfully\n")

# Map to ULF
print("Mapping Wazuh alert to ULF format...")
try:
    mapper = WazuhToULFMapper()
    
    # FIXED: Unpack the tuple returned by map_alert
    ulf, warnings, summary = mapper.map_alert(wazuh_alert)
    
    print("✓ Mapping successful\n")
    
    # Print validation summary first
    print("=" * 80)
    print("VALIDATION SUMMARY:")
    print("=" * 80)
    print(json.dumps(summary, indent=2))
    
    if warnings:
        print("\n" + "=" * 80)
        print("⚠️  VALIDATION WARNINGS:")
        print("=" * 80)
        for warning in warnings:
            print(f"  • {warning}")
    
    # Print ULF output
    print("\n" + "=" * 80)
    print("UNIFIED LOG FORMAT (ULF) OUTPUT:")
    print("=" * 80)
    ulf_dict = ulf.model_dump()
    print(json.dumps(ulf_dict, indent=2, default=str))
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY:")
    print("=" * 80)
    print(f"Alert ID: {ulf_dict['alert_id']}")
    print(f"OCSF Class: {ulf_dict['class_name']} ({ulf_dict['class_uid']})")
    print(f"Severity: {ulf_dict['severity']} ({ulf_dict['severity_id']})")
    print(f"Finding Title: {ulf_dict['finding']['title']}")
    print(f"Source IP: {ulf_dict.get('src_endpoint', {}).get('ip', 'N/A')}")
    print(f"Destination IP: {ulf_dict.get('dst_endpoint', {}).get('ip', 'N/A')}")
    print(f"MITRE Techniques: {', '.join(ulf_dict['finding']['types']) if ulf_dict['finding']['types'] else 'None'}")
    print(f"Processing Status: {ulf_dict['processing_status']}")
    
    print("\n✅ ALL TESTS PASSED!")

except Exception as e:
    print(f"✗ Mapping failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)