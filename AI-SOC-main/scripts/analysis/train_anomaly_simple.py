"""
Anomaly Detection Model Training - Simplified Standalone
Isolation Forest for detecting unusual security alert patterns
"""

import numpy as np
from pymongo import MongoClient
from pathlib import Path
import logging
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def extract_features(alert):
    """Extract 11 behavioral features from an alert"""
    features = []
    
    # 1. Severity (0-15)
    rule = alert.get('rule', {})
    features.append(rule.get('level', 5))
    
    # 2. MITRE tactic ID (0-13, -1 for unknown)
    tactics = rule.get('mitre', {}).get('tactic', [])
    tactic_map = {
        'reconnaissance': 0, 'resource_development': 1, 'initial_access': 2,
        'execution': 3, 'persistence': 4, 'privilege_escalation': 5,
        'defense_evasion': 6, 'credential_access': 7, 'discovery': 8,
        'lateral_movement': 9, 'collection': 10, 'command_and_control': 11,
        'exfiltration': 12, 'impact': 13
    }
    if isinstance(tactics, list) and len(tactics) > 0:
        tactic = tactics[0].lower().replace(' ', '_')
        features.append(tactic_map.get(tactic, -1))
    else:
        features.append(-1)
    
    # 3. Has MITRE technique
    techniques = rule.get('mitre', {}).get('id', [])
    features.append(1 if (isinstance(techniques, list) and len(techniques) > 0) else 0)
    
    # 4. Rule ID hash (for frequency patterns)
    rule_id = rule.get('id', '')
    features.append(hash(rule_id) % 1000)
    
    # 5-8. Temporal features
    from datetime import datetime
    ts = alert.get('timestamp')
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
    
    features.append(ts.hour)  # Hour (0-23)
    features.append(ts.weekday())  # Day of week (0-6)
    features.append(1 if ts.weekday() >= 5 else 0)  # Weekend flag
    features.append(1 if 9 <= ts.hour <= 17 else 0)  # Business hours
    
    # 9. Agent hash
    agent_name = alert.get('agent', {}).get('name', 'unknown')
    features.append(hash(agent_name) % 100)
    
    # 10. Description length
    features.append(len(rule.get('description', '')))
    
    # 11. Number of groups
    groups = rule.get('groups', [])
    features.append(len(groups) if isinstance(groups, list) else 0)
    
    return features


def main():
    logger.info("="*60)
    logger.info("ANOMALY DETECTION TRAINING")
    logger.info("="*60)
    
    # Load alerts
    logger.info("\n📥 Loading alerts...")
    client = MongoClient("mongodb://localhost:27017/")
    alerts = list(client.soar.alerts_processed.find({}))
    logger.info(f"   Loaded {len(alerts):,} alerts")
    
    # Extract features
    logger.info("\n🔍 Extracting features...")
    features = []
    for alert in alerts:
        try:
            features.append(extract_features(alert))
        except:
            pass
    
    features = np.array(features)
    logger.info(f"   Extracted {len(features):,} feature vectors")
    logger.info(f"   Features per alert: {features.shape[1]}")
    
    # Scale
    logger.info("\n⚖️  Scaling...")
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    # Split
    split = int(len(features_scaled) * 0.8)
    train = features_scaled[:split]
    test = features_scaled[split:]
    logger.info(f"   Train: {len(train):,}, Test: {len(test):,}")
    
    # Train
    logger.info("\n🎯 Training Isolation Forest...")
    logger.info("   100 trees, 10% contamination")
    
    model = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        random_state=42,
        n_jobs=-1
    )
    model.fit(train)
    
    logger.info("   ✅ Training complete!")
    
    # Evaluate on train
    logger.info("\n📊 Training Set Evaluation:")
    train_preds = model.predict(train)
    train_scores = model.score_samples(train)
    n_anom_train = np.sum(train_preds == -1)
    rate_train = n_anom_train / len(train) * 100
    
    logger.info(f"   Anomalies: {n_anom_train:,} / {len(train):,} ({rate_train:.1f}%)")
    logger.info(f"   Score range: [{train_scores.min():.3f}, {train_scores.max():.3f}]")
    
    # Evaluate on test
    logger.info("\n📊 Test Set Evaluation:")
    test_preds = model.predict(test)
    test_scores = model.score_samples(test)
    n_anom_test = np.sum(test_preds == -1)
    rate_test = n_anom_test / len(test) * 100
    
    logger.info(f"   Anomalies: {n_anom_test:,} / {len(test):,} ({rate_test:.1f}%)")
    logger.info(f"   Score range: [{test_scores.min():.3f}, {test_scores.max():.3f}]")
    
    # Consistency
    diff = abs(rate_train - rate_test)
    logger.info(f"\n🎯 Consistency Check:")
    logger.info(f"   Train rate: {rate_train:.1f}%")
    logger.info(f"   Test rate:  {rate_test:.1f}%")
    logger.info(f"   Difference: {diff:.1f}%")
    
    if diff < 3:
        logger.info(f"   ✅ GOOD - Consistent detection")
    else:
        logger.info(f"   ⚠️  WARNING - Large variance")
    
    # Top anomalies
    logger.info(f"\n🔍 Top 5 Anomalies (test set):")
    top_idx = np.argsort(test_scores)[:5]
    for idx in top_idx:
        logger.info(f"   Score: {test_scores[idx]:.3f}")
    
    # Save
    logger.info(f"\n💾 Saving...")
    Path("models").mkdir(exist_ok=True)
    
    save_data = {
        'model': model,
        'scaler': scaler,
        'trained': True,
        'n_features': 11,
        'metrics': {
            'train_anomaly_rate': float(rate_train),
            'test_anomaly_rate': float(rate_test),
            'consistency': float(diff)
        }
    }
    
    with open("models/anomaly_detector.pkl", 'wb') as f:
        pickle.dump(save_data, f)
    
    logger.info("   ✅ Saved to models/anomaly_detector.pkl")
    
    logger.info("\n" + "="*60)
    logger.info("✅ TRAINING COMPLETE!")
    logger.info("="*60)
    logger.info(f"\n🎯 Summary:")
    logger.info(f"   Anomaly Rate: ~{rate_test:.1f}%")
    logger.info(f"   Consistency: {diff:.1f}% difference")
    logger.info(f"   Features: 11 behavioral features")
    logger.info(f"\n✅ Ready for deployment!")


if __name__ == "__main__":
    main()
