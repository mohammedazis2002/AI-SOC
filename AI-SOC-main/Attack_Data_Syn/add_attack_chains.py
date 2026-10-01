"""
Attack Chain Generator
Adds coordinated attack chain patterns to existing alerts
"""
import json
import random
from datetime import timedelta
from collections import defaultdict

def generate_attack_chains(alerts, chain_percentage=0.08):
    """
    Modify alerts to create realistic attack chains
    ~8% of alerts will be part of coordinated multi-stage attacks
    """
    
    # Define attack chain templates
    ATTACK_CHAIN_TEMPLATES = [
        {
            "name": "Ransomware Campaign",
            "stages": ["Initial Access", "Execution", "Defense Evasion", "Credential Access", "Lateral Movement", "Impact"],
            "min_devices": 3,
            "max_devices": 8,
            "duration_minutes": (30, 240)
        },
        {
            "name": "Data Exfiltration",
            "stages": ["Initial Access", "Execution", "Discovery", "Collection", "Exfiltration"],
            "min_devices": 2,
            "max_devices": 5,
            "duration_minutes": (60, 360)
        },
        {
            "name": "APT Lateral Movement",
            "stages": ["Initial Access", "Persistence", "Privilege Escalation", "Lateral Movement", "Credential Access", "Discovery"],
            "min_devices": 4,
            "max_devices": 12,
            "duration_minutes": (120, 720)
        },
        {
            "name": "Supply Chain Attack",
            "stages": ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Command and Control"],
            "min_devices": 5,
            "max_devices": 15,
            "duration_minutes": (90, 480)
        },
        {
            "name": "Cloud Breach",
            "stages": ["Initial Access", "Credential Access", "Privilege Escalation", "Persistence", "Exfiltration"],
            "min_devices": 3,
            "max_devices": 7,
            "duration_minutes": (45, 300)
        },
        {
            "name": "Network Reconnaissance",
            "stages": ["Reconnaissance", "Discovery", "Lateral Movement", "Collection"],
            "min_devices": 2,
            "max_devices": 6,
            "duration_minutes": (20, 180)
        }
    ]
    
    print(f"\nGenerating attack chains for {chain_percentage*100:.0f}% of alerts...")
    
    num_chains = int(len(alerts) * chain_percentage / 5)  # Avg 5 alerts per chain
    chains_created = 0
    alerts_modified = 0
    
    # Group alerts by tactic for easier selection
    alerts_by_tactic = defaultdict(list)
    for idx, alert in enumerate(alerts):
        if 'mitre' in alert['rule']:
            tactics = alert['rule']['mitre']['tactic']
            for tactic in tactics:
                alerts_by_tactic[tactic].append(idx)
    
    # Track which alerts are already in chains
    used_alerts = set()
    
    # Generate attack chains
    for _ in range(num_chains):
        template = random.choice(ATTACK_CHAIN_TEMPLATES)
        
        # Select number of devices for this chain
        num_devices = random.randint(template['min_devices'], template['max_devices'])
        
        # Select alerts for each stage
        chain_alert_indices = []
        selected_tactics = []
        
        for stage in template['stages']:
            # Find alerts matching this tactic that aren't already used
            available = [idx for idx in alerts_by_tactic.get(stage, []) if idx not in used_alerts]
            if available:
                selected_idx = random.choice(available)
                chain_alert_indices.append(selected_idx)
                selected_tactics.append(stage)
                used_alerts.add(selected_idx)
        
        if len(chain_alert_indices) < 3:
            # Not enough alerts for a meaningful chain
            continue
        
        # Sort alerts by current timestamp
        chain_alert_indices.sort(key=lambda idx: alerts[idx]['timestamp'])
        
        # Set base timestamp for chain
        base_timestamp = alerts[chain_alert_indices[0]]['timestamp']
        base_dt = datetime.fromisoformat(base_timestamp.replace('Z', '+00:00'))
        
        # Calculate duration
        duration_mins = random.randint(*template['duration_minutes'])
        
        # Generate attack chain ID
        campaign_id = f"CAMPAIGN-{random.randint(10000, 99999)}"
        
        # Select target devices
        device_pool = []
        # Start with workstation or external entry point
        entry_devices = [h for h in HOSTNAMES if h.startswith(('WORKSTATION', 'WEB', 'VPN', 'Proxy'))]
        device_pool.append(random.choice(entry_devices))
        
        # Add intermediate devices (servers, network)
        intermediate_devices = [h for h in HOSTNAMES if h.startswith(('APP', 'DB', 'DC', 'Switch', 'Router'))]
        device_pool.extend(random.sample(intermediate_devices, min(num_devices - 2, len(intermediate_devices))))
        
        # Add target device (DB, cloud, or critical server)
        target_devices = [h for h in HOSTNAMES if h.startswith(('DB', 'AWS', 'Azure', 'GCP', 'DC'))]
        if target_devices:
            device_pool.append(random.choice(target_devices))
        
        # Assign timestamps and devices to chain alerts
        for i, alert_idx in enumerate(chain_alert_indices):
            # Progress through timeline
            offset_minutes = int((i / len(chain_alert_indices)) * duration_mins)
            new_timestamp = base_dt + timedelta(minutes=offset_minutes)
            alerts[alert_idx]['timestamp'] = new_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            
            # Assign device from pool (with progression)
            if i < len(device_pool):
                device = device_pool[i]
            else:
                device = random.choice(device_pool)
            
            alerts[alert_idx]['agent']['name'] = device
            alerts[alert_idx]['agent']['ip'] = generate_ip()
            
            # Add attack chain metadata
            alerts[alert_idx]['data']['attack_chain'] = {
                'campaign_id': campaign_id,
               'campaign_name': template['name'],
                'stage_number': i + 1,
                'total_stages': len(chain_alert_indices),
                'stage_name': selected_tactics[i] if i < len(selected_tactics) else 'Unknown',
                'is_chain_alert': True
            }
            
            # Increase severity for chain alerts
            if alerts[alert_idx]['rule']['level'] < 10:
                alerts[alert_idx]['rule']['level'] = random.randint(10, 12)
            
            alerts_modified += 1
        
        chains_created += 1
        
        if chains_created % 10 == 0:
            print(f"  Created {chains_created} attack chains...")
    
    print(f"\n✅ Attack chain generation complete:")
    print(f"   - Chains created: {chains_created}")
    print(f"   - Alerts modified: {alerts_modified} ({alerts_modified/len(alerts)*100:.1f}%)")
    print(f"   - Chain types: {len(ATTACK_CHAIN_TEMPLATES)} different templates")
    
    return alerts

# Import necessary components
from datetime import datetime
import sys
sys.path.append('.')

# Load the existing alerts
print("Loading existing alerts...")
with open('synthetic_wazuh_alerts.json', 'r') as f:
    alerts = json.load(f)

print(f"Loaded {len(alerts):,} alerts")

# Import hostname list from generator
exec(open('generate_synthetic_wazuh_alerts.py').read())

# Generate attack chains
alerts_with_chains = generate_attack_chains(alerts, chain_percentage=0.08)

# Re-sort by timestamp
alerts_with_chains.sort(key=lambda x: x['timestamp'])

# Save updated alerts
print("\nSaving updated alerts with attack chains...")
with open('synthetic_wazuh_alerts.json', 'w') as f:
    json.dump(alerts_with_chains, f, indent=2)

# Also save as NDJSON
with open('synthetic_wazuh_alerts.ndjson', 'w') as f:
    for alert in alerts_with_chains:
        f.write(json.dumps(alert) + '\n')

print("✅ Done! Attack chains added to dataset.")

# Print statistics
chain_alerts = [a for a in alerts_with_chains if a.get('data', {}).get('attack_chain', {}).get('is_chain_alert')]
print(f"\nFinal Statistics:")
print(f"  Total alerts: {len(alerts_with_chains):,}")
print(f"  Chain alerts: {len(chain_alerts):,} ({len(chain_alerts)/len(alerts_with_chains)*100:.1f}%)")
print(f"  Standalone alerts: {len(alerts_with_chains) - len(chain_alerts):,}")

# Show sample campaigns
campaigns = {}
for alert in chain_alerts:
    campaign_id = alert['data']['attack_chain']['campaign_id']
    campaign_name = alert['data']['attack_chain']['campaign_name']
    if campaign_id not in campaigns:
        campaigns[campaign_id] = {
            'name': campaign_name,
            'count': 0,
            'devices': set(),
            'stages': set()
        }
    campaigns[campaign_id]['count'] += 1
    campaigns[campaign_id]['devices'].add(alert['agent']['name'])
    campaigns[campaign_id]['stages'].add(alert['data']['attack_chain']['stage_name'])

print(f"\nSample Attack Campaigns:")
for i, (cid, info) in enumerate(list(campaigns.items())[:5], 1):
    print(f"  {i}. {cid} - {info['name']}")
    print(f"     Alerts: {info['count']}, Devices: {len(info['devices'])}, Stages: {len(info['stages'])}")
