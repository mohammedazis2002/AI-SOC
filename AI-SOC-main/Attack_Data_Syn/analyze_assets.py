import json
from collections import Counter

print("Loading alerts...")
with open('synthetic_wazuh_alerts.json', 'r') as f:
    alerts = json.load(f)

print("\n" + "="*70)
print("ASSET AND LOG SOURCE ANALYSIS")
print("="*70)

# Asset types
agent_names = [alert['agent']['name'] for alert in alerts]
unique_agents = set(agent_names)

# Categorize by asset type
asset_types = Counter()
for agent in unique_agents:
    if agent.startswith('WEB-'):
        asset_types['Web Servers'] += 1
    elif agent.startswith('DB-'):
        asset_types['Database Servers'] += 1
    elif agent.startswith('APP-'):
        asset_types['Application Servers'] += 1
    elif agent.startswith('DC-'):
        asset_types['Domain Controllers'] += 1
    elif agent.startswith('MAIL-'):
        asset_types['Mail Servers'] += 1
    elif agent.startswith('WORKSTATION-'):
        asset_types['Workstations'] += 1

print(f"\nTotal Unique Assets: {len(unique_agents)}")
print("\nAsset Type Distribution:")
for asset_type, count in sorted(asset_types.items()):
    print(f"  {asset_type:25s}: {count:3d} assets")

# Log sources
log_locations = Counter([alert['location'] for alert in alerts])
print(f"\nLog Sources ({len(log_locations)} unique):")
for location, count in log_locations.most_common():
    print(f"  {location:40s}: {count:6,} alerts")

# Alert categories/decoders
decoders = Counter([alert['decoder']['name'] for alert in alerts])
print(f"\nAlert Categories:")
for decoder, count in decoders.most_common():
    print(f"  {decoder:25s}: {count:6,} alerts")

print("\n" + "="*70)
print("MISSING LOG SOURCES:")
print("="*70)
missing_sources = [
    "Firewall logs (Palo Alto, Fortinet, pfSense)",
    "Cloud logs (AWS CloudTrail, Azure Activity, GCP Audit)",
    "EDR/Endpoint logs (CrowdStrike, SentinelOne, Carbon Black)",
    "Container logs (Docker, Kubernetes, containerd)",
    "Network device logs (Cisco, Juniper, switches, routers)",
    "IDS/IPS logs (Snort, Suricata)",
    "Proxy logs (Squid, Zscaler)",
    "VPN logs (OpenVPN, Cisco AnyConnect)",
    "Load balancer logs (F5, Nginx, HAProxy)",
]

for i, source in enumerate(missing_sources, 1):
    print(f"  {i}. {source}")

print("\n" + "="*70)
