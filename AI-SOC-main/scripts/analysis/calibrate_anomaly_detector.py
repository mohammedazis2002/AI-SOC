"""
Anomaly Detection Contamination Calibration
Tests multiple contamination values and visualizes results
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
    """Extract 11 behavioral features"""
    features = []
    rule = alert.get('rule', {})
    features.append(rule.get('level', 5))
    
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
    
    techniques = rule.get('mitre', {}).get('id', [])
    features.append(1 if (isinstance(techniques, list) and len(techniques) > 0) else 0)
    features.append(hash(rule.get('id', '')) % 1000)
    
    from datetime import datetime
    ts = alert.get('timestamp')
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
    
    features.extend([
        ts.hour, ts.weekday(),
        1 if ts.weekday() >= 5 else 0,
        1 if 9 <= ts.hour <= 17 else 0,
        hash(alert.get('agent', {}).get('name', 'unknown')) % 100,
        len(rule.get('description', '')),
        len(rule.get('groups', []))
    ])
    
    return features


def main():
    logger.info("="*70)
    logger.info("ANOMALY DETECTION - CONTAMINATION CALIBRATION")
    logger.info("="*70)
    
    # Load data
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
    logger.info(f"   Features: {len(features):,} x {features.shape[1]}")
    
    # Scale
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    # Test multiple contamination values
    contamination_values = [0.01, 0.02, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30]
    
    logger.info("\n" + "="*70)
    logger.info("TESTING MULTIPLE CONTAMINATION VALUES")
    logger.info("="*70)
    
    results = []
    
    for contam in contamination_values:
        logger.info(f"\n🧪 Testing contamination = {contam:.0%}")
        
        # Train model
        model = IsolationForest(
            n_estimators=100,
            contamination=contam,
            random_state=42,
            n_jobs=-1
        )
        model.fit(features_scaled)
        
        # Get predictions and scores
        predictions = model.predict(features_scaled)
        scores = model.score_samples(features_scaled)
        
        # Calculate metrics
        n_anomalies = np.sum(predictions == -1)
        anomaly_rate = n_anomalies / len(predictions) * 100
        
        # Score statistics
        anomaly_scores = scores[predictions == -1]
        normal_scores = scores[predictions == 1]
        
        score_gap = normal_scores.min() - anomaly_scores.max()
        
        results.append({
            'contamination': contam,
            'n_anomalies': n_anomalies,
            'rate': anomaly_rate,
            'score_min': scores.min(),
            'score_max': scores.max(),
            'score_mean': scores.mean(),
            'score_std': scores.std(),
            'anomaly_score_max': anomaly_scores.max() if len(anomaly_scores) > 0 else 0,
            'normal_score_min': normal_scores.min() if len(normal_scores) > 0 else 0,
            'gap': score_gap
        })
        
        logger.info(f"   Anomalies: {n_anomalies:,} ({anomaly_rate:.1f}%)")
        logger.info(f"   Score range: [{scores.min():.3f}, {scores.max():.3f}]")
        logger.info(f"   Separation gap: {score_gap:.3f}")
    
    # Display comparison table
    logger.info("\n" + "="*70)
    logger.info("CONTAMINATION COMPARISON TABLE")
    logger.info("="*70)
    logger.info(f"{'Contam':<8} {'Count':<8} {'Rate':<8} {'Score Range':<20} {'Gap':<8}")
    logger.info("-" * 70)
    
    for r in results:
        logger.info(
            f"{r['contamination']:<8.0%} "
            f"{r['n_anomalies']:<8,} "
            f"{r['rate']:<8.1f}% "
            f"[{r['score_min']:.3f}, {r['score_max']:.3f}] "
            f"{r['gap']:<8.3f}"
        )
    
    # Score distribution analysis
    logger.info("\n" + "="*70)
    logger.info("SCORE DISTRIBUTION ANALYSIS")
    logger.info("="*70)
    
    # Fit one model to analyze score distribution
    model = IsolationForest(n_estimators=100, contamination=0.10, random_state=42, n_jobs=-1)
    model.fit(features_scaled)
    all_scores = model.score_samples(features_scaled)
    
    # Find percentiles
    percentiles = [1, 2, 5, 10, 15, 20, 25, 30, 50]
    logger.info(f"\n📊 Score Percentiles:")
    logger.info(f"{'Percentile':<12} {'Score':<10} {'# Alerts':<10}")
    logger.info("-" * 35)
    
    for p in percentiles:
        percentile_score = np.percentile(all_scores, p)
        n_below = np.sum(all_scores <= percentile_score)
        logger.info(f"{p:<12}%  {percentile_score:<10.3f} {n_below:<10,}")
    
    # Recommendations
    logger.info("\n" + "="*70)
    logger.info("RECOMMENDATIONS")
    logger.info("="*70)
    
    logger.info("\n📌 Based on the analysis:")
    logger.info("\n1. **Conservative (Low False Positives):**")
    logger.info("   - Use contamination = 1-5%")
    logger.info("   - Only flags the most extreme anomalies")
    logger.info("   - Good for production environments where false alarms are costly")
    
    logger.info("\n2. **Balanced (Recommended for SOC):**")
    logger.info("   - Use contamination = 5-15%")
    logger.info("   - Catches most anomalies while keeping false positives manageable")
    logger.info("   - Standard for security operations")
    
    logger.info("\n3. **Aggressive (High Coverage):**")
    logger.info("   - Use contamination = 15-30%")
    logger.info("   - Flags more potential issues")
    logger.info("   - Good for threat hunting, requires more analyst review")
    
    logger.info("\n💡 **How to Choose:**")
    logger.info("   - Start conservative (5%)")
    logger.info("   - Have analysts review flagged anomalies for 1 week")
    logger.info("   - If too many false positives → decrease contamination")
    logger.info("   - If missing obvious anomalies → increase contamination")
    logger.info("   - Typical sweet spot for SOCs: 8-12%")
    
    # Optionally save model with recommended contamination
    logger.info("\n❓ Which contamination value would you like to use?")
    logger.info("   Options: 0.01, 0.02, 0.05, 0.08, 0.10, 0.12, 0.15, 0.20, 0.25, 0.30")
    logger.info("\n   (Or run this script again with your chosen value)")
    
    logger.info("\n" + "="*70)
    logger.info("CALIBRATION COMPLETE")
    logger.info("="*70)


if __name__ == "__main__":
    main()
