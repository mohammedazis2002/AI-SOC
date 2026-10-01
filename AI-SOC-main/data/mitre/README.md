"""
Usage Guide: MITRE Pattern Library

This guide explains how to use the generated MITRE ATT&CK pattern library
for enhanced alert enrichment in Model 2.

## Generated Files

1. `data/mitre/enterprise-attack.json` - Official MITRE ATT&CK Enterprise data (raw)
2. `data/mitre/attack_patterns.json` - Processed pattern library for enrichment

## Pattern Library Statistics

- **Total Patterns:** 887 MITRE techniques - 600 unique techniques (parent)
- **File Size:** 365KB (17,861 lines)
- **Coverage:** All 14 MITRE tactics
- **Format:** JSON with keywords and technique IDs

## How It Works

The pattern library contains keyword mappings for each MITRE technique:

```json
{
  "execution": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "keywords": ["powershell", "ps1", "encodedcommand", "invoke-expression"]
    }
  ],
  "credential-access": [
    {
      "technique_id": "T1003.001",
      "technique_name": "LSASS Memory",
      "keywords": ["mimikatz", "lsass", "sekurlsa", "procdump"]
    }
  ]
}
```

## Using the Pattern Library

### In Attack Stage Service (Automatic)

The pattern library is automatically loaded when the service starts:

```python
# backend/services/ml/attack_stage_service.py
enricher = MITREEnricher(pattern_library_path='data/mitre/attack_patterns.json')
```

### In Standalone Scripts

```python
from backend.services.ml.attack_stage.mitre_enricher import MITREEnricher

# Initialize with pattern library
enricher = MITREEnricher('data/mitre/attack_patterns.json')

# Enrich an alert
alert = {
    'alert_id': 'ALT-12345',
    'message': 'Detected PowerShell execution',
    'process': {
        'cmd_line': 'powershell.exe -encodedCommand ABC123'
    }
}

mitre_data, attempts = enricher.enrich(alert)

if mitre_data:
    print(f"Tactic: {mitre_data['dominant_tactic']}")
    print(f"Method: {mitre_data['method']}")
else:
    print(f"Enrichment failed. Attempts: {attempts}")
```

## Regenerating the Pattern Library

To update the pattern library with the latest MITRE data:

```powershell
cd c:\Users\Shruthi Kannan\Documents\SOAR\soar-platform
python scripts/build_pattern_library.py
```

This will:
1. Download latest MITRE ATT&CK Enterprise data
2. Extract keywords from technique descriptions
3. Generate updated `data/mitre/attack_patterns.json`

**Recommended frequency:** Monthly or after major MITRE updates

## Enrichment Success Rates

With the pattern library, expected enrichment success rates:

- **Method 1 (SIEM Data):** ~40% of alerts
- **Method 2 (Sigma Mapping):** ~15% of remaining
- **Method 3 (Pattern Matching):** ~70% of remaining ⭐ **Improved with library**
- **Method 4 (Process Analysis):** ~10% of remaining
- **Method 5 (Network Analysis):** ~5% of remaining

**Overall Expected Success:** >90% (up from ~70% without library)

## Monitoring Enrichment Effectiveness

Check enrichment statistics via API:

```http
GET http://localhost:5003/queue/stats
```

Response shows:
```json
{
  "enrichment": {
    "total_attempts": 1000,
    "success_rate": 0.92,
    "method_breakdown": {
      "pattern_matching": {
        "count": 450,
        "percentage": 45.0
      }
    }
  }
}
```

## Customizing Patterns

To add custom patterns or improve accuracy:

1. Edit `data/mitre/attack_patterns.json`
2. Add keywords specific to your environment
3. Restart the attack stage service

Example custom pattern:

```json
{
  "execution": [
    {
      "technique_id": "CUSTOM-001",
      "technique_name": "Internal Tool Execution",
      "keywords": ["your-custom-tool", "internal-script"]
    }
  ]
}
```

## Troubleshooting

### Pattern library not found

```
Failed to load pattern library: [Errno 2] No such file or directory
```

**Solution:** Run `python scripts/build_pattern_library.py` to generate it

### Low enrichment success rate

**Solution:** 
1. Check queue stats to identify which methods are failing
2. Review unmapped alerts to find common patterns
3. Add custom patterns for those alerts

### Pattern library outdated

**Solution:** Regenerate monthly or subscribe to MITRE ATT&CK updates

---

## Summary

The MITRE pattern library significantly improves enrichment accuracy by providing:
✅ 600+ technique keyword mappings  
✅ Complete coverage of all 14 tactics  
✅ Easy customization for environment-specific patterns  

This reduces unmapped alerts and improves Model 2's ability to accurately identify attack stages.
