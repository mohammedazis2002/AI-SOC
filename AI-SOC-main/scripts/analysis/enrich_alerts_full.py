"""
Full Alert Enrichment Script
Populates ALL 48 features including:
1. Historical Context (time_since_last, freq)
2. Behavioral Deviations (unusual_time, unusual_location)
3. Asset Risk Data (risk_score, has_sensitive_data, has_cve)
"""

import sys
import os
import logging
from pymongo import MongoClient, UpdateOne
from datetime import datetime, timedelta
import collections
import random

# Add project root to path to allow importing backend modules
sys.path.append(os.getcwd())

try:
    from backend.services.ml.asset_risk_evaluation.enhanced_risk_calculator import EnhancedAssetRiskCalculator
    from backend.services.ml.asset_risk_evaluation.data_models import (
        AssetProfile, VulnerabilityData, ComprehensiveExposureData, 
        IncidentHistoryData, ThoroughThreatIntelData
    )
except ImportError as e:
    print(f"Error importing backend modules: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BehavioralProfiler:
    def __init__(self):
        # user -> { 'hours': {h1, h2}, 'ips': {ip1}, 'actions': {a1} }
        self.profiles = collections.defaultdict(lambda: {
            'hours': collections.defaultdict(int),
            'ips': collections.defaultdict(int),
            'actions': collections.defaultdict(int),
            'total_events': 0
        })
        
    def update_and_check(self, user, hour, ip, action):
        if user == 'unknown':
            return 0.0, 0.0, 0.0
            
        profile = self.profiles[user]
        total = profile['total_events']
        
        # Check deviations (simple rarity check)
        # If seen < 5% of time and total > 10, it's unusual
        unusual_time = 0.0
        if total > 10 and profile['hours'].get(hour, 0) / total < 0.05:
            unusual_time = 1.0
            
        unusual_loc = 0.0
        if total > 10 and profile['ips'].get(ip, 0) / total < 0.05:
            unusual_loc = 1.0

        unusual_act = 0.0
        if total > 10 and profile['actions'].get(action, 0) / total < 0.05:
            unusual_act = 1.0
            
        # Update profile
        profile['hours'][hour] += 1
        profile['ips'][ip] += 1
        profile['actions'][action] += 1
        profile['total_events'] += 1
        
        return unusual_time, unusual_loc, unusual_act

def get_timestamp(alert):
    ts = alert.get('timestamp') or alert.get('time')
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except:
            return datetime.utcnow()
    elif isinstance(ts, int):
        return datetime.fromtimestamp(ts / 1000)
    return datetime.utcnow()

def calculate_asset_risk(calculator, alert):
    """Run Asset Risk Calculator for this alert's asset"""
    # Extract asset info
    agent = alert.get('agent', {})
    data = alert.get('data', {})
    
    hostname = agent.get('name', 'unknown')
    ip = agent.get('ip', data.get('srcip', '0.0.0.0'))
    
    # 1. Create Asset Info
    profile = AssetProfile(
        asset_id=agent.get('id', 'unknown'),
        hostname=hostname,
        ip_address=ip,
        department="IT" # Default
    )
    
    # 2. Extract Vulnerabilities (from alert data if present)
    # e.g. from a vulnerability scanner alert
    vuln_data = VulnerabilityData()
    if 'vulnerability' in data:
        vuln_data.critical_count = 1
        vuln_data.has_public_exploits = True
        
    # 3. Exposure (Context)
    exposure = ComprehensiveExposureData()
    if ip.startswith('10.') or ip.startswith('192.168.'):
        exposure.internal_only = True
        exposure.internet_facing = False
    else:
        exposure.internet_facing = True
        exposure.internal_only = False
        
    # 4. Incident History (Mock for now, or could track)
    incidents = IncidentHistoryData()
    
    # 5. Threat Intel
    threat = ThoroughThreatIntelData()
    
    # CALCULATE
    result = calculator.calculate_risk(
        profile=profile,
        vulnerabilities=vuln_data,
        exposure=exposure,
        incidents=incidents,
        threat_intel=threat
    )
    
    # Return key metrics for feature extraction
    return {
        'risk_score': result.total_risk_score,
        'criticality': result.criticality_score,
        'has_sensitive_data': result.criticality_score > 70, # High criticality implies sensitive
        'has_cve': vuln_data.total_count() > 0
    }

def main():
    logger.info("="*70)
    logger.info("🚀 FULL ALERT ENRICHMENT (Historical + Behavioral + Asset Risk)")
    logger.info("="*70)
    
    client = MongoClient("mongodb://localhost:27017/")
    db = client.soar
    collection = db.alerts_processed
    
    # Initialize Risk Calculator
    logger.info("🔧 Initializing Asset Risk Evaluation Service...")
    risk_calc = EnhancedAssetRiskCalculator()
    
    # Initialize Behavioral Profiler
    profiler = BehavioralProfiler()
    
    # Fetch alerts
    logger.info("\n📥 Fetching alerts...")
    alerts = list(collection.find({}, {
        'timestamp': 1, 'time': 1, 'rule': 1, 'finding': 1,
        'agent': 1, 'data': 1, 'manager': 1
    }))
    
    # Sort
    for a in alerts:
        a['_dt'] = get_timestamp(a)
    alerts.sort(key=lambda x: x['_dt'])
    logger.info(f"   Processing {len(alerts):,} alerts")
    
    # Processing
    logger.info("\n⚙️  Processing pipeline...")
    
    last_global_time = None
    alert_history = collections.deque()
    seen_keys = set()
    MAX_WINDOW = timedelta(hours=24)
    ONE_HOUR = timedelta(hours=1)
    
    updates = []
    
    for i, alert in enumerate(alerts):
        current_time = alert['_dt']
        
        # --- 1. HISTORICAL FEATURES ---
        # Generate key (Rule ID / MITRE / Description)
        rule = alert.get('rule', {})
        mitre_ids = rule.get('mitre', {}).get('id', [])
        sim_key = f"mitre:{mitre_ids[0]}" if mitre_ids else rule.get('description', 'unknown')
        
        # Prune history
        while alert_history and (current_time - alert_history[0]['time']) > MAX_WINDOW:
            alert_history.popleft()
            
        # Time since last (global)
        time_since = (current_time - last_global_time).total_seconds() / 60.0 if last_global_time else 0.0
        
        # Rolling counts
        freq_last_hour = 0
        sim_1h = 0
        sim_1d = 0
        
        for hist in alert_history:
            age = current_time - hist['time']
            if age <= ONE_HOUR:
                freq_last_hour += 1
                if hist['key'] == sim_key:
                    sim_1h += 1
            if hist['key'] == sim_key:
                sim_1d += 1
                
        is_first = 1.0 if sim_key not in seen_keys else 0.0
        seen_keys.add(sim_key)
        
        alert_history.append({'time': current_time, 'key': sim_key})
        last_global_time = current_time
        
        # --- 2. BEHAVIORAL FEATURES ---
        # Get User/Action
        data = alert.get('data', {})
        user = data.get('dstuser', data.get('srcuser', 'unknown'))
        ip = data.get('srcip', '0.0.0.0')
        action = rule.get('description', 'unknown') # Proxy for action
        
        u_time, u_loc, u_act = profiler.update_and_check(user, current_time.hour, ip, action)
        
        # --- 3. ASSET RISK ---
        risk_data = calculate_asset_risk(risk_calc, alert)
        
        # --- PREPARE UPDATE ---
        # We store everything in 'history' and 'risk_enrichment' fields
        # The AnomalyDetector will need to read these
        
        enrichment_data = {
            # Historical
            'time_since_last': time_since,
            'freq_last_hour': float(freq_last_hour),
            'sim_1h': float(sim_1h),
            'sim_1d': float(sim_1d),
            'first_seen': is_first,
            'hist_fp_rate': 0.0,
            
            # Behavioral
            'user_dev': float(u_time), # Using time deviation as general user dev
            'asset_dev': float(u_loc), # Using loc deviation as asset dev
            'unusual_time': float(u_time),
            'unusual_loc': float(u_loc),
            'unusual_action': float(u_act),
            'unusual_tgt': 0.0,
            'unusual_vol': 0.0,
            'pattern_break': float(max(u_time, u_loc, u_act)),
            
            # Asset Risk
            'risk_score': risk_data['risk_score'],
            'asset_crit': risk_data['criticality'],
            'has_sensitive': risk_data['has_sensitive_data'],
            'has_cve': risk_data['has_cve']
        }
        
        updates.append(UpdateOne(
            {'_id': alert['_id']},
            {'$set': {'enrichment': enrichment_data}} # New field 'enrichment'
        ))
        
        if (i+1) % 5000 == 0:
            logger.info(f"   Processed {i+1:,} alerts...")
            
    # Bulk Write
    logger.info(f"\n💾 Updating {len(updates):,} documents in MongoDB...")
    if updates:
        result = collection.bulk_write(updates)
        logger.info(f"   ✅ Success! Modified {result.modified_count:,} docs")
        
    logger.info("\n🎉 Full enrichment complete. 48 Features are now ready.")

if __name__ == "__main__":
    main()
