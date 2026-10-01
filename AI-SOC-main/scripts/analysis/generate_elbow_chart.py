"""
Anomaly Detection - Elbow Chart Visualization
Helps identify optimal contamination value by visualizing score distribution
"""

import numpy as np
from pymongo import MongoClient
import logging
import matplotlib.pyplot as plt
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
    logger.info("="*60)
    logger.info("ANOMALY DETECTION - ELBOW CHART GENERATION")
    logger.info("="*60)
    
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
    
    # Scale features
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    # Train model with moderate contamination to get all scores
    logger.info("\n🎯 Training Isolation Forest...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.10,  # Arbitrary for scoring
        random_state=42,
        n_jobs=-1
    )
    model.fit(features_scaled)
    
    # Get anomaly scores for all alerts
    logger.info("\n📊 Calculating anomaly scores...")
    scores = model.score_samples(features_scaled)
    
    # Sort scores (lowest = most anomalous)
    sorted_scores = np.sort(scores)
    
    logger.info(f"   Score range: [{sorted_scores[0]:.3f}, {sorted_scores[-1]:.3f}]")
    logger.info(f"   Score mean: {scores.mean():.3f}")
    logger.info(f"   Score std: {scores.std():.3f}")
    
    # Create visualizations
    logger.info("\n📈 Creating visualizations...")
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('Anomaly Detection - Contamination Parameter Selection', fontsize=16, fontweight='bold')
    
    # 1. Score Distribution (Histogram)
    ax1 = axes[0, 0]
    ax1.hist(scores, bins=100, color='skyblue', edgecolor='black', alpha=0.7)
    ax1.axvline(scores.mean(), color='red', linestyle='--', linewidth=2, label=f'Mean: {scores.mean():.3f}')
    ax1.set_xlabel('Anomaly Score', fontsize=12)
    ax1.set_ylabel('Frequency', fontsize=12)
    ax1.set_title('1. Anomaly Score Distribution', fontsize=14, fontweight='bold')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # 2. Sorted Scores (Elbow Curve) - THE KEY CHART
    ax2 = axes[0, 1]
    percentiles = np.arange(0, 100, 0.1)
    percentile_scores = np.percentile(sorted_scores, percentiles)
    
    ax2.plot(percentiles, percentile_scores, linewidth=2, color='darkblue')
    ax2.set_xlabel('Percentile (%)', fontsize=12)
    ax2.set_ylabel('Anomaly Score', fontsize=12)
    ax2.set_title('2. Elbow Curve (Sorted Scores)', fontsize=14, fontweight='bold')
    ax2.grid(True, alpha=0.3)
    
    # Add reference lines for common contamination values
    contamination_values = [1, 2, 5, 10, 15, 20, 25, 30]
    for contam in contamination_values:
        score_at_contam = np.percentile(sorted_scores, contam)
        ax2.axvline(contam, color='red', linestyle='--', alpha=0.3, linewidth=1)
        ax2.text(contam, sorted_scores[-1], f'{contam}%', rotation=90, 
                verticalalignment='bottom', fontsize=8)
    
    # 3. Score Differences (Rate of Change) - Shows where elbow is
    ax3 = axes[1, 0]
    score_diffs = np.diff(sorted_scores)
    x_diff = np.arange(1, len(score_diffs) + 1) / len(scores) * 100
    
    ax3.plot(x_diff, score_diffs, linewidth=1, color='green', alpha=0.7)
    ax3.set_xlabel('Percentile (%)', fontsize=12)
    ax3.set_ylabel('Score Difference (Rate of Change)', fontsize=12)
    ax3.set_title('3. Score Change Rate (Find Steep Drops)', fontsize=14, fontweight='bold')
    ax3.grid(True, alpha=0.3)
    ax3.set_xlim([0, 30])  # Focus on first 30% where anomalies are
    
    # Find largest drops
    largest_drops_idx = np.argsort(score_diffs)[:10]
    largest_drops_pct = largest_drops_idx / len(scores) * 100
    for pct in largest_drops_pct:
        if pct < 30:  # Only show first 30%
            ax3.axvline(pct, color='red', linestyle=':', alpha=0.5)
    
    # 4. Contamination Comparison Table (Visual)
    ax4 = axes[1, 1]
    ax4.axis('off')
    
    # Create comparison data
    comparison_data = []
    contamination_test = [1, 2, 5, 8, 10, 12, 15, 20, 25, 30]
    
    for contam in contamination_test:
        threshold_score = np.percentile(sorted_scores, contam)
        n_anomalies = int(len(scores) * contam / 100)
        comparison_data.append([
            f"{contam}%",
            f"{n_anomalies:,}",
            f"{threshold_score:.3f}"
        ])
    
    # Create table
    table = ax4.table(
        cellText=comparison_data,
        colLabels=['Contamination', '# Anomalies', 'Score Threshold'],
        cellLoc='center',
        loc='center',
        colWidths=[0.3, 0.3, 0.4]
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2)
    
    # Style header
    for i in range(3):
        table[(0, i)].set_facecolor('#4CAF50')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    # Highlight recommended rows
    recommended_rows = [3, 4, 5]  # 8%, 10%, 12%
    for row in recommended_rows:
        for col in range(3):
            table[(row + 1, col)].set_facecolor('#FFEB3B')
    
    ax4.set_title('4. Contamination Values Comparison', fontsize=14, fontweight='bold', pad=20)
    
    # Add recommendation text
    recommendation_text = (
        "📌 HOW TO READ THE ELBOW CURVE (Chart 2):\n"
        "• Look for where the curve bends sharply (the 'elbow')\n"
        "• Anomalies are on the LEFT (low percentiles)\n"
        "• Normal alerts are on the RIGHT (high percentiles)\n"
        "• Choose contamination at the elbow point\n\n"
        "💡 TYPICAL RECOMMENDATIONS:\n"
        "• Conservative: 5-8% (fewer false positives)\n"
        "• Balanced: 8-12% (highlighted in yellow)\n"
        "• Aggressive: 15-20% (more coverage)"
    )
    
    fig.text(0.02, 0.02, recommendation_text, fontsize=10, 
             verticalalignment='bottom', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout(rect=[0, 0.15, 1, 0.96])
    
    # Save figure
    output_path = 'anomaly_elbow_chart.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    logger.info(f"   ✅ Saved visualization to: {output_path}")
    
    # Also show it
    plt.show()
    
    # Print analysis
    logger.info("\n" + "="*60)
    logger.info("ELBOW ANALYSIS")
    logger.info("="*60)
    
    logger.info("\n📊 Score Percentiles:")
    for p in [1, 2, 5, 8, 10, 12, 15, 20, 25, 30]:
        score = np.percentile(sorted_scores, p)
        logger.info(f"   {p:2d}%:  Score threshold = {score:.3f}  ({int(len(scores)*p/100):,} alerts)")
    
    # Find steepest drops
    logger.info("\n📉 Steepest Score Drops (Potential Elbow Points):")
    drop_indices = np.argsort(score_diffs)[:5]
    for idx in drop_indices:
        percentile = idx / len(scores) * 100
        drop_size = score_diffs[idx]
        if percentile < 30:  # Only relevant in first 30%
            logger.info(f"   At {percentile:.1f}%:  Drop = {drop_size:.4f}")
    
    logger.info("\n💡 RECOMMENDATION:")
    logger.info("   1. Look at Chart 2 (Elbow Curve)")
    logger.info("   2. Find where the curve bends sharply")
    logger.info("   3. That percentile is your optimal contamination")
    logger.info("   4. For most SOCs, the elbow is around 8-12%")
    
    logger.info("\n" + "="*60)
    logger.info("✅ VISUALIZATION COMPLETE")
    logger.info("="*60)
    logger.info(f"\n📊 Open: {output_path}")


if __name__ == "__main__":
    main()
