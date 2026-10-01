"""
Enrich Alerts with Historical Features
Calculates rolling window metrics and historical context for Anomaly Detection
"""

import logging
from pymongo import MongoClient, UpdateOne
from datetime import datetime, timedelta
import collections

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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

def get_similarity_key(alert):
    """Generate a key to identify 'similar' alerts"""
    # Prefer rule ID or MITRE ID, fallback to description/title
    rule = alert.get('rule', {})
    mitre = rule.get('mitre', {})
    mitre_ids = mitre.get('id', [])
    
    if mitre_ids:
        return f"mitre:{mitre_ids[0]}"
    
    return rule.get('description', 'unknown')

def main():
    logger.info("="*70)
    logger.info("⏱️  CALCULATING HISTORICAL FEATURES")
    logger.info("="*70)
    
    client = MongoClient("mongodb://localhost:27017/")
    db = client.soar
    collection = db.alerts_processed
    
    # 1. Fetch all alerts and sort by time
    logger.info("\n📥 Fetching and sorting alerts...")
    alerts = list(collection.find({}, {'timestamp': 1, 'time': 1, 'rule': 1, 'finding': 1}))
    
    # Add parsed timestamp object for sorting
    for a in alerts:
        a['_dt'] = get_timestamp(a)
    
    # Sort chronological
    alerts.sort(key=lambda x: x['_dt'])
    logger.info(f"   Processing {len(alerts):,} alerts")
    
    # 2. Iterate and calculate features
    logger.info("\n🧮 Calculating rolling window metrics...")
    
    # State tracking
    last_global_time = None
    alert_history = collections.deque()  # Keep recent alerts for frequency counts
    seen_keys = set()
    
    # Using 24h max window for history retention
    MAX_WINDOW = timedelta(hours=24)
    ONE_HOUR = timedelta(hours=1)
    
    updates = []
    
    for i, alert in enumerate(alerts):
        current_time = alert['_dt']
        sim_key = get_similarity_key(alert)
        
        # Prune history older than 24h
        while alert_history and (current_time - alert_history[0]['time']) > MAX_WINDOW:
            alert_history.popleft()
        
        # Calculate time_since_last (global)
        if last_global_time:
            time_since = (current_time - last_global_time).total_seconds() / 60.0 # minutes
        else:
            time_since = 0.0
        
        # Calculate rolling counts with explicit delta comparisons
        freq_last_hour = 0
        sim_1h = 0
        sim_1d = 0
                
        for hist_alert in alert_history:
            h_time = hist_alert['time']
            h_key = hist_alert['key']
            
            age = current_time - h_time
            
            # Global frequency last hour
            if age <= ONE_HOUR:
                freq_last_hour += 1
                
                # Similarity last hour
                if h_key == sim_key:
                    sim_1h += 1
            
            # Similarity last day (history is max 24h so check all)
            if h_key == sim_key:
                sim_1d += 1
        
        # First seen?
        is_first_seen = 1.0 if sim_key not in seen_keys else 0.0
        seen_keys.add(sim_key)
        
        # Update history
        alert_history.append({
            'time': current_time,
            'key': sim_key
        })
        last_global_time = current_time
        
        # Prepare Update including static temporal features
        history_data = {
            # Standard metrics
            'time_since_last': time_since,
            'freq_last_hour': float(freq_last_hour),
            'sim_1h': float(sim_1h),
            'sim_1d': float(sim_1d),
            'first_seen': is_first_seen,
            'hist_fp_rate': 0.0,  # Placeholder
            
            # Temporal features (added per request)
            'element_hour': float(current_time.hour),
            'element_day': float(current_time.weekday()),
            'element_is_weekend': float(current_time.weekday() >= 5),
            'element_is_business_hours': float(9 <= current_time.hour <= 17)
        }
        
        updates.append(UpdateOne(
            {'_id': alert['_id']},
            {'$set': {'history': history_data}}
        ))
        
        if (i+1) % 5000 == 0:
            logger.info(f"   Prepared {i+1:,} alerts...")

    # 3. Bulk Write
    logger.info(f"\n💾 Writing {len(updates):,} updates to MongoDB...")
    if updates:
        result = collection.bulk_write(updates)
        logger.info(f"   ✅ Modified {result.modified_count:,} documents")
    else:
        logger.info("   ⚠️  No updates needed")
        
    logger.info("\nRefreshed historical features! Now run the analysis/training again.")
    print("DONE")

if __name__ == "__main__":
    main()
