import json
from collections import Counter, defaultdict
from datetime import datetime

# Load the alerts
print("Loading alerts...")
with open('synthetic_wazuh_alerts.json', 'r') as f:
    alerts = json.load(f)

print(f"\n{'='*60}")
print(f"SYNTHETIC WAZUH ALERTS - DATASET ANALYSIS")
print(f"{'='*60}")

print(f"\n📊 Total Alerts Generated: {len(alerts):,}")

# Severity distribution
severity_counts = Counter()
for alert in alerts:
    level = alert['rule']['level']
    if level >= 13:
        severity_counts['critical'] += 1
    elif level >= 10:
        severity_counts['high'] += 1
    elif level >= 7:
        severity_counts['medium'] += 1
    else:
        severity_counts['low'] += 1

print(f"\n🎯 Severity Distribution:")
for severity in ['critical', 'high', 'medium', 'low']:
    count = severity_counts[severity]
    percentage = (count / len(alerts)) * 100
    print(f"  {severity.capitalize():8s}: {count:6,} ({percentage:5.2f}%)")

# MITRE technique coverage
mitre_techniques = set()
tactic_distribution = defaultdict(set)
for alert in alerts:
    if 'mitre' in alert['rule']:
        for tech_id in alert['rule']['mitre']['id']:
            mitre_techniques.add(tech_id)
            tactics = alert['rule']['mitre']['tactic']
            for tactic in tactics:
                tactic_distribution[tactic].add(tech_id)

print(f"\n🛡️  MITRE ATT&CK Coverage:")
print(f"  Unique Techniques: {len(mitre_techniques)}/887")
print(f"  Coverage: {(len(mitre_techniques)/887)*100:.1f}%")

print(f"\n📋 Techniques by Tactic:")
for tactic in sorted(tactic_distribution.keys()):
    count = len(tactic_distribution[tactic])
    print(f"  {tactic:25s}: {count:3d} techniques")

# Category distribution
category_counts = Counter()
for alert in alerts:
    category = alert['decoder']['name']
    category_counts[category] += 1

print(f"\n🔍 Attack Category Distribution:")
for category, count in category_counts.most_common():
    percentage = (count / len(alerts)) * 100
    print(f"  {category.replace('_', ' ').title():25s}: {count:6,} ({percentage:5.2f}%)")

# Time range
timestamps = [datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00')) for alert in alerts[:100]]
if timestamps:
    min_time = min(timestamps)
    max_time = max(timestamps)
    print(f"\n📅 Time Range (sample):")
    print(f"  Start: {min_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  End:   {max_time.strftime('%Y-%m-%d %H:%M:%S')}")

# Zero-day attacks
zero_day_count = sum(1 for alert in alerts if alert.get('data', {}).get('zero_day', False))
print(f"\n⚠️  Zero-Day Attacks: {zero_day_count} ({(zero_day_count/len(alerts))*100:.2f}%)")

# Unique assets
unique_agents = set(alert['agent']['name'] for alert in alerts)
print(f"\n💻 Unique Assets: {len(unique_agents)}")

# Top targeted hosts
host_counts = Counter(alert['agent']['name'] for alert in alerts)
print(f"\n🎯 Top 10 Most Targeted Hosts:")
for host, count in host_counts.most_common(10):
    print(f"  {host:20s}: {count:4d} alerts")

print(f"\n{'='*60}")
print("✅ Dataset is ready for ML model training!")
print(f"{'='*60}")
print("\nFiles generated:")
print("  📄 synthetic_wazuh_alerts.json  (structured JSON)")
print("  📄 synthetic_wazuh_alerts.ndjson (line-delimited for streaming)")
