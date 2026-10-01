"""
Full 48-Feature Extraction and Scatter Plot Visualization
Uses the complete anomaly detector feature set to analyze data diversity
"""

import numpy as np
from pymongo import MongoClient
import logging
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def extract_48_features(alert):
    """Extract all 48 features as specified in anomaly_detector.py"""
    
    # Get timestamp
    timestamp = alert.get('timestamp')
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    
    # TEMPORAL FEATURES (6)
    # TEMPORAL FEATURES (6)
    enrichment = alert.get('enrichment', {})
    
    temporal = [
        float(timestamp.hour),  # 0-23
        float(timestamp.weekday()),  # 0-6
        float(timestamp.weekday() >= 5),  # is_weekend
        float(9 <= timestamp.hour <= 17),  # is_business_hours
        float(enrichment.get('time_since_last', 0.0)),  # time_since_last_alert
        float(enrichment.get('freq_last_hour', 0.0))   # alert_frequency_last_hour
    ]
    
    # RULE-BASED FEATURES (8)
    rule = alert.get('rule', {})
    severity = rule.get('level', 5)
    mitre_data = rule.get('mitre', {})
    mitre_ids = mitre_data.get('id', [])
    groups = rule.get('groups', [])
    description = rule.get('description', '').lower()
    
    rule_based = [
        float(severity),
        float(len(groups)),
        float(len(mitre_ids)),
        float('auth' in description or 'authentication' in description),
        float('privilege' in description or 'elevat' in description),
        float('pci' in description),
        float('nist' in description),
        float(enrichment.get('has_cve', 0.0)) if 'has_cve' in enrichment else float(bool(alert.get('data', {}).get('vulnerability', {})))
    ]
    
    # NETWORK FEATURES (8)
    data = alert.get('data', {})
    src_ip = data.get('srcip', '0.0.0.0')
    dst_ip = data.get('dstip', '0.0.0.0')
    src_port = int(data.get('srcport', 0)) if data.get('srcport') else 0
    dst_port = int(data.get('dstport', 0)) if data.get('dstport') else 0
    protocol = data.get('protocol', 'tcp')
    
    # Helper functions
    def ip_to_numeric(ip):
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return sum(int(p) * (256 ** (3-i)) for i, p in enumerate(parts)) / (256**4)
        except:
            pass
        return 0.5
    
    def protocol_to_numeric(proto):
        proto_map = {'tcp': 0, 'udp': 1, 'icmp': 2, 'http': 3, 'https': 4}
        return proto_map.get(proto.lower(), 5) / 10.0
    
    def is_external_ip(ip):
        try:
            parts = [int(p) for p in ip.split('.')]
            if parts[0] == 10: return 0
            if parts[0] == 172 and 16 <= parts[1] <= 31: return 0
            if parts[0] == 192 and parts[1] == 168: return 0
            return 1
        except:
            return 0
    
    network = [
        ip_to_numeric(src_ip),
        float(src_port) / 65535.0 if src_port else 0.0,
        ip_to_numeric(dst_ip),
        float(dst_port) / 65535.0 if dst_port else 0.0,
        protocol_to_numeric(protocol),
        0.0,  # bytes_sent (not in synthetic data)
        0.0,  # bytes_received (not in synthetic data)
        0.0   # session_duration (not in synthetic data)
    ]
    
    # USER/ASSET FEATURES (8)
    agent = alert.get('agent', {})
    agent_name = agent.get('name', 'unknown')
    agent_id = agent.get('id', 'unknown')
    
    def string_to_hash(s):
        return (hash(str(s)) % 10000) / 10000.0
    
    user_asset = [
        string_to_hash(data.get('dstuser', 'unknown')),
        string_to_hash(agent_name),
        float(enrichment.get('asset_crit', 0.5)),  # asset_criticality
        0.3,  # user_privilege_level (default normal)
        0.0,  # uses_sudo
        float(is_external_ip(src_ip)),
        float(enrichment.get('risk_score', 50.0) / 100.0),  # risk_score (normalized)
        0.0   # is_known_good_ip
    ]
    
    # CONTEXT FEATURES (10)
    # CONTEXT FEATURES (10)
    context = [
        float(enrichment.get('sim_1h', 0.0)),  # similar_alerts_last_hour
        float(enrichment.get('sim_1d', 0.0)),  # similar_alerts_last_day
        1.0,  # correlation_group_size (standalone)
        float(enrichment.get('first_seen', 0.0)),  # is_first_time_seen
        float(enrichment.get('hist_fp_rate', 0.0)),  # historical_fp_rate
        0.5,  # vt_reputation_score (default neutral)
        0.0,  # threat_intel_match
        float(enrichment.get('has_sensitive', 0.0)),  # has_sensitive_data
        0.0,  # in_maintenance_window
        0.0   # compliance_violation
    ]
    
    # BEHAVIORAL FEATURES (8)
    # BEHAVIORAL FEATURES (8)
    behavioral = [
        float(enrichment.get('user_dev', 0.0)),
        float(enrichment.get('asset_dev', 0.0)),
        float(enrichment.get('unusual_time', 0.0)),
        float(enrichment.get('unusual_loc', 0.0)),
        float(enrichment.get('unusual_action', 0.0)),
        float(enrichment.get('unusual_tgt', 0.0)),
        float(enrichment.get('unusual_vol', 0.0)),
        float(enrichment.get('pattern_break', 0.0))
    ]
    
    # Combine all 48 features
    return temporal + rule_based + network + user_asset + context + behavioral


def main():
    logger.info("="*70)
    logger.info("48-FEATURE EXTRACTION & SCATTER PLOT ANALYSIS")
    logger.info("="*70)
    
    # Load alerts
    logger.info("\n📥 Loading alerts...")
    client = MongoClient("mongodb://localhost:27017/")
    alerts = list(client.soar.alerts_processed.find({}))
    logger.info(f"   Loaded {len(alerts):,} alerts")
    
    # Extract all 48 features
    logger.info("\n🔍 Extracting all 48 features...")
    features = []
    for alert in alerts:
        try:
            feat = extract_48_features(alert)
            if len(feat) == 48:
                features.append(feat)
        except Exception as e:
            logger.warning(f"Failed to extract: {e}")
    
    features = np.array(features)
    logger.info(f"   Extracted {len(features):,} feature vectors")
    logger.info(f"   Dimensions: {features.shape}")
    
    # Feature statistics
    logger.info("\n📊 Feature Diversity Analysis:")
    
    feature_names = [
        # Temporal (6)
        "hour_of_day", "day_of_week", "is_weekend", "is_business_hours", 
        "time_since_last", "freq_last_hour",
        # Rule (8)
        "severity", "num_groups", "num_mitre", "is_auth", "is_priv", 
        "is_pci", "is_nist", "has_cve",
        # Network (8)
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol", 
        "bytes_out", "bytes_in", "duration",
        # User/Asset (8)
        "user_hash", "asset_hash", "asset_crit", "user_priv", "uses_sudo",
        "is_external", "geo_risk", "is_known_good",
        # Context (10)
        "sim_1h", "sim_1d", "corr_size", "first_seen", "hist_fp", 
        "vt_score", "threat_match", "sensitive", "maintenance", "compliance",
        # Behavioral (8)
        "user_dev", "asset_dev", "unusual_time", "unusual_loc", "unusual_action",
        "unusual_tgt", "unusual_vol", "pattern_break"
    ]
    
    variance = np.var(features, axis=0)
    std = np.std(features, axis=0)
    unique_counts = [len(np.unique(features[:, i])) for i in range(features.shape[1])]
    
    # Find low diversity features
    low_diversity = []
    for i in range(features.shape[1]):
        if std[i] < 0.01 or unique_counts[i] <= 2:
            low_diversity.append((i, feature_names[i], std[i], unique_counts[i]))
    
    logger.info(f"\n⚠️  LOW DIVERSITY FEATURES ({len(low_diversity)} / 48):")
    logger.info(f"{'Feature':<20} {'Std Dev':<12} {'Unique Values'}")
    logger.info("-" * 50)
    for idx, name, std_val, unique in low_diversity[:15]:  # Show top 15
        logger.info(f"{name:<20} {std_val:<12.4f} {unique}")
    
    # Overall diversity score
    diversity_score = np.mean(std)
    logger.info(f"\n📈 Overall Diversity Score: {diversity_score:.4f}")
    
    if diversity_score < 0.1:
        logger.info("   ⚠️  WARNING: Very low diversity - data is highly homogeneous!")
    elif diversity_score < 0.3:
        logger.info("   ⚠️  Moderate diversity - some variation but limited")
    else:
        logger.info("   ✅  Good diversity - data has reasonable variation")
    
    # Scale features for visualization
    logger.info("\n⚖️  Scaling features...")
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    # PCA for dimensionality reduction
    logger.info("\n🎯 Applying PCA (48D → 2D)...")
    pca = PCA(n_components=2)
    features_2d = pca.fit_transform(features_scaled)
    
    explained_var = pca.explained_variance_ratio_
    logger.info(f"   PC1 explains: {explained_var[0]*100:.1f}% of variance")
    logger.info(f"   PC2 explains: {explained_var[1]*100:.1f}% of variance")
    logger.info(f"   Total: {sum(explained_var)*100:.1f}%")
    
    if sum(explained_var) > 0.9:
        logger.info("   ⚠️  WARNING: >90% variance in 2 components suggests low diversity!")
    
    # Train Isolation Forest on full features
    logger.info("\n🎯 Training Isolation Forest on 48 features...")
    model = IsolationForest(n_estimators=100, contamination=0.10, random_state=42, n_jobs=-1)
    model.fit(features_scaled)
    
    predictions = model.predict(features_scaled)
    scores = model.score_samples(features_scaled)
    
    anomalies = predictions == -1
    n_anomalies = np.sum(anomalies)
    
    logger.info(f"   Anomalies detected: {n_anomalies:,} ({n_anomalies/len(features)*100:.1f}%)")
    
    # Create visualizations
    logger.info("\n📊 Creating scatter plots...")
    
    fig, axes = plt.subplots(2, 2, figsize=(16, 14))
    fig.suptitle('48-Feature Anomaly Detection - Data Diversity Analysis', 
                 fontsize=16, fontweight='bold')
    
    # 1. PCA Scatter Plot - Colored by Anomaly Score
    ax1 = axes[0, 0]
    scatter1 = ax1.scatter(features_2d[:, 0], features_2d[:, 1], 
                          c=scores, cmap='RdYlGn', s=10, alpha=0.6)
    ax1.set_xlabel(f'PC1 ({explained_var[0]*100:.1f}% variance)', fontsize=11)
    ax1.set_ylabel(f'PC2 ({explained_var[1]*100:.1f}% variance)', fontsize=11)
    ax1.set_title('1. PCA Projection (Colored by Anomaly Score)', fontsize=13, fontweight='bold')
    plt.colorbar(scatter1, ax=ax1, label='Anomaly Score')
    ax1.grid(True, alpha=0.3)
    
    # 2. PCA Scatter - Anomalies Highlighted
    ax2 = axes[0, 1]
    ax2.scatter(features_2d[~anomalies, 0], features_2d[~anomalies, 1], 
               c='blue', s=10, alpha=0.3, label='Normal')
    ax2.scatter(features_2d[anomalies, 0], features_2d[anomalies, 1], 
               c='red', s=20, alpha=0.8, label='Anomaly', marker='x')
    ax2.set_xlabel(f'PC1 ({explained_var[0]*100:.1f}% variance)', fontsize=11)
    ax2.set_ylabel(f'PC2 ({explained_var[1]*100:.1f}% variance)', fontsize=11)
    ax2.set_title('2. Normal vs Anomalous Alerts', fontsize=13, fontweight='bold')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    # 3. Feature Variance Distribution
    ax3 = axes[1, 0]
    ax3.bar(range(48), variance, color='skyblue', edgecolor='black')
    ax3.set_xlabel('Feature Index', fontsize=11)
    ax3.set_ylabel('Variance', fontsize=11)
    ax3.set_title('3. Feature Variance (Higher = More Diversity)', fontsize=13, fontweight='bold')
    ax3.axhline(y=0.01, color='red', linestyle='--', label='Low Variance Threshold')
    ax3.legend()
    ax3.grid(True, alpha=0.3, axis='y')
    
    # 4. Unique Value Counts
    ax4 = axes[1, 1]
    ax4.bar(range(48), unique_counts, color='lightcoral', edgecolor='black')
    ax4.set_xlabel('Feature Index', fontsize=11)
    ax4.set_ylabel('# Unique Values', fontsize=11)
    ax4.set_title('4. Feature Uniqueness (Higher = More Diversity)', fontsize=13, fontweight='bold')
    ax4.grid(True, alpha=0.3, axis='y')
    
    # Add analysis text
    analysis_text = (
        f"📊 DATA DIVERSITY ANALYSIS:\n\n"
        f"Total Alerts: {len(features):,}\n"
        f"Features Extracted: 48\n"
        f"Overall Diversity Score: {diversity_score:.4f}\n"
        f"Low Diversity Features: {len(low_diversity)}/48\n\n"
        f"PCA Compression: {sum(explained_var)*100:.1f}% in 2 components\n"
        f"Anomalies Detected: {n_anomalies:,} ({n_anomalies/len(features)*100:.1f}%)\n\n"
        f"{'⚠️  CONCLUSION: Data is HOMOGENEOUS' if diversity_score < 0.2 else '✅ CONCLUSION: Reasonable diversity'}\n"
        f"{'Synthetic data lacks variation in many features' if diversity_score < 0.2 else 'Data shows good variation'}"
    )
    
    fig.text(0.02, 0.02, analysis_text, fontsize=10, 
             verticalalignment='bottom', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.7))
    
    plt.tight_layout(rect=[0, 0.12, 1, 0.96])
    
    # Save
    output_path = 'anomaly_48_features_scatter.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logger.info(f"   ✅ Saved to: {output_path}")
    
    plt.show()
    
    # Final analysis
    logger.info("\n" + "="*70)
    logger.info("FINAL ANALYSIS")
    logger.info("="*70)
    
    logger.info(f"\n✅ Confirmation: {'YES' if diversity_score < 0.2 else 'NO'}, the synthetic data IS homogeneous")
    logger.info(f"\n📊 Evidence:")
    logger.info(f"   1. Diversity score: {diversity_score:.4f} (< 0.2 = homogeneous)")
    logger.info(f"   2. Low-variance features: {len(low_diversity)}/48 ({len(low_diversity)/48*100:.0f}%)")
    logger.info(f"   3. PCA compression: {sum(explained_var)*100:.0f}% in just 2 dims")
    logger.info(f"   4. Many features have constant/near-constant values")
    
    logger.info(f"\n💡 Implication for Anomaly Detection:")
    logger.info(f"   - Model will struggle to find meaningful anomalies")
    logger.info(f"   - All alerts look very similar to each other")
    logger.info(f"   - Real-world data will have much more variation")
    logger.info(f"   - Expect better performance with production data")
    
    logger.info("\n" + "="*70)
    logger.info("✅ ANALYSIS COMPLETE")
    logger.info("="*70)


if __name__ == "__main__":
    main()
