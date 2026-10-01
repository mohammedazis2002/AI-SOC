import json
from collections import defaultdict
from datetime import datetime

print("Loading alerts...")
with open('synthetic_wazuh_alerts.json', 'r') as f:
    alerts = json.load(f)

# Find chain alerts
chain_alerts = [a for a in alerts if a.get('data', {}).get('attack_chain', {}).get('is_chain_alert')]

print(f"\n{'='*80}")
print("ATTACK CHAIN ANALYSIS")
print(f"{'='*80}")

print(f"\nOverall Statistics:")
print(f"  Total alerts: {len(alerts):,}")
print(f"  Chain alerts: {len(chain_alerts):,} ({len(chain_alerts)/len(alerts)*100:.1f}%)")
print(f"  Standalone alerts: {len(alerts) - len(chain_alerts):,}")

# Group by campaign
campaigns = defaultdict(list)
for alert in chain_alerts:
    campaign_id = alert['data']['attack_chain']['campaign_id']
    campaigns[campaign_id].append(alert)

print(f"  Unique attack campaigns: {len(campaigns)}")

# Campaign statistics
campaign_sizes = [len(alerts) for alerts in campaigns.values()]
print(f"\nCampaign Size Distribution:")
print(f"  Average alerts per campaign: {sum(campaign_sizes)/len(campaign_sizes):.1f}")
print(f"  Min alerts per campaign: {min(campaign_sizes)}")
print(f"  Max alerts per campaign: {max(campaign_sizes)}")

# Show sample campaigns
print(f"\n{'='*80}")
print("SAMPLE ATTACK CHAINS (Top 5 largest campaigns)")
print(f"{'='*80}\n")

sorted_campaigns = sorted(campaigns.items(), key=lambda x: len(x[1]), reverse=True)

for i, (campaign_id, chain_alerts_list) in enumerate(sorted_campaigns[:5], 1):
    chain_alerts_list.sort(key=lambda x: x['data']['attack_chain']['stage_number'])
    
    campaign_name = chain_alerts_list[0]['data']['attack_chain']['campaign_name']
    devices = set([a['agent']['name'] for a in chain_alerts_list])
    stages = [(a['data']['attack_chain']['stage_number'], a['data']['attack_chain']['stage_name']) 
              for a in chain_alerts_list]
    
    start_time = datetime.fromisoformat(chain_alerts_list[0]['timestamp'].replace('Z', '+00:00'))
    end_time = datetime.fromisoformat(chain_alerts_list[-1]['timestamp'].replace('Z', '+00:00'))
    duration = end_time - start_time
    
    print(f"Campaign #{i}: {campaign_id}")
    print(f"  Type: {campaign_name}")
    print(f"  Alerts: {len(chain_alerts_list)}")
    print(f"  Devices affected: {len(devices)}")
    print(f"  Duration: {duration}")
    print(f"  Timeline:")
    
    for alert in chain_alerts_list:
        stage_num = alert['data']['attack_chain']['stage_number']
        stage_name = alert['data']['attack_chain']['stage_name']
        device = alert['agent']['name']
        technique = alert['rule']['mitre']['technique'][0] if alert['rule']['mitre']['technique'] else 'Unknown'
        severity_map = {1: 'Low', 5: 'Low', 7: 'Med', 8: 'Med', 9: 'Med', 10: 'High', 11: 'High', 12: 'High', 13: 'Crit', 14: 'Crit', 15: 'Crit'}
        severity = severity_map.get(alert['rule']['level'], 'Med')
        timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
        
        print(f"    [{stage_num}] {timestamp.strftime('%H:%M:%S')} | {device:20s} | {stage_name:25s} | {technique[:40]:40s} | {severity}")
    
    print()

print(f"{'='*80}")
print("Attack Chain Types:")
print(f"{'='*80}")

campaign_types = defaultdict(int)
for chain_alerts_list in campaigns.values():
    campaign_type = chain_alerts_list[0]['data']['attack_chain']['campaign_name']
    campaign_types[campaign_type] += 1

for campaign_type, count in sorted(campaign_types.items(), key=lambda x: x[1], reverse=True):
    percentage = (count / len(campaigns)) * 100
    print(f"  {campaign_type:30s}: {count:4d} campaigns ({percentage:5.1f}%)")

print(f"\n{'='*80}")
