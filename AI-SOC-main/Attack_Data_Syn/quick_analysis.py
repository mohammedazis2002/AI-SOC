import json

print("Analyzing dataset...")
with open('synthetic_wazuh_alerts.json', 'r') as f:
    alerts = json.load(f)

print(f"\nTotal alerts: {len(alerts):,}")
print(f"Unique assets: {len(set([x['agent']['name'] for x in alerts])):,}")

locs = set([x['location'] for x in alerts])
print(f"Unique log sources: {len(locs)}")

print("\nLog source distribution:")
from collections import Counter
loc_counts = Counter([x['location'] for x in alerts])
for loc, count in sorted(loc_counts.items(), key=lambda x: x[1], reverse=True)[:30]:
    print(f"  {loc[:60]:60s}: {count:5,} alerts")

# Asset types
print("\nAsset type summary:")
asset_types = Counter()
for alert in alerts:
    name = alert['agent']['name']
    if 'FW-' in name:
        asset_types['Firewalls'] += 1
    elif 'AWS-' in name:
        asset_types['AWS Cloud'] += 1
    elif 'Azure-' in name:
        asset_types['Azure Cloud'] += 1
    elif 'GCP-' in name:
        asset_types['GCP Cloud'] += 1
    elif 'K8S-' in name:
        asset_types['Kubernetes'] += 1
    elif 'Docker-' in name:
        asset_types['Docker'] += 1
    elif 'EDR-' in name:
        asset_types['EDR/Endpoint'] += 1
    elif 'Switch-' in name:
        asset_types['Network Switches'] += 1
    elif 'Router-' in name:
        asset_types['Routers'] += 1
    elif 'VPN-' in name:
        asset_types['VPN Gateways'] += 1
    elif 'Proxy-' in name:
        asset_types['Proxies'] += 1
    elif 'LB-' in name:
        asset_types['Load Balancers'] += 1
    elif 'IDS-' in name:
        asset_types['IDS/IPS'] += 1
    else:
        asset_types['Traditional Servers'] += 1

for asset_type, count in sorted(asset_types.items(), key=lambda x: x[1], reverse=True):
    print(f"  {asset_type:25s}: {count:5,} alerts")

print("\nDone!")
