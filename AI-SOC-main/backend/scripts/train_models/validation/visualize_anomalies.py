"""
Anomaly Visualization Script
============================
Visualizes anomaly detection results from validate_anomaly.py
Creates plots showing:
- Anomaly scores over time
- Score distribution histogram
- Feature correlations with anomaly scores
- Time series of key behavioral features
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import numpy as np

# Set up plotting style
plt.style.use('default')
sns.set_palette("husl")

def load_validation_results():
    """Load the anomaly validation results CSV"""
    results_file = Path("../../data/features/v1/anomaly_validation_results.csv")
    if not results_file.exists():
        print(f"Validation results not found at {results_file}")
        print("Run validate_anomaly.py first to generate results.")
        return None

    df = pd.read_csv(results_file)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

def plot_anomaly_scores_over_time(df):
    """Plot anomaly scores over time with anomaly highlights"""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10), sharex=True)

    # Plot anomaly scores
    ax1.plot(df['timestamp'], df['anomaly_score'], 'b-', alpha=0.7, linewidth=1)
    ax1.scatter(df['timestamp'], df['anomaly_score'],
                c=df['is_anomaly'], cmap='RdYlGn_r',
                s=50, alpha=0.8, edgecolors='black', linewidth=0.5)

    ax1.set_title('Anomaly Scores Over Time', fontsize=14, fontweight='bold')
    ax1.set_ylabel('Anomaly Score', fontsize=12)
    ax1.grid(True, alpha=0.3)
    ax1.axhline(y=df['anomaly_score'].mean(), color='red', linestyle='--', alpha=0.7,
                label='.2f')
    ax1.legend()

    # Colorbar for anomalies
    sm = plt.cm.ScalarMappable(cmap='RdYlGn_r', norm=plt.Normalize(vmin=0, vmax=1))
    sm.set_array([])
    cbar = plt.colorbar(sm, ax=ax1, orientation='vertical', pad=0.02)
    cbar.set_label('Anomaly Flag (1=Anomaly, 0=Normal)')

    # Plot key features over time
    features_to_plot = ['total_alerts', 'peak_severity', 'failed_logins_count', 'unique_sources']
    colors = ['purple', 'orange', 'red', 'brown']

    for i, feature in enumerate(features_to_plot):
        if feature in df.columns:
            ax2.plot(df['timestamp'], df[feature], color=colors[i], label=feature,
                    linewidth=2, alpha=0.8)

    ax2.set_title('Key Behavioral Features Over Time', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Timestamp', fontsize=12)
    ax2.set_ylabel('Feature Value', fontsize=12)
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('anomaly_timeline.png', dpi=300, bbox_inches='tight')
    plt.show()

def plot_score_distribution(df):
    """Plot histogram of anomaly scores"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # Histogram
    n, bins, patches = ax1.hist(df['anomaly_score'], bins=30, alpha=0.7,
                               color='skyblue', edgecolor='black', linewidth=0.5)

    # Color the bars based on anomaly status
    for patch, score in zip(patches, bins[:-1]):
        if score < df['anomaly_score'].quantile(0.05):  # Bottom 5% as "anomalous"
            patch.set_facecolor('red')
        elif score > df['anomaly_score'].quantile(0.95):  # Top 5% as "normal"
            patch.set_facecolor('green')

    ax1.set_title('Anomaly Score Distribution', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Anomaly Score', fontsize=12)
    ax1.set_ylabel('Frequency', fontsize=12)
    ax1.grid(True, alpha=0.3)
    ax1.axvline(df['anomaly_score'].mean(), color='red', linestyle='--',
                label='.2f')
    ax1.axvline(df['anomaly_score'].median(), color='orange', linestyle='--',
                label='.2f')
    ax1.legend()

    # Box plot
    anomaly_data = df['anomaly_score'][df['is_anomaly'] == 1]
    normal_data = df['anomaly_score'][df['is_anomaly'] == 0]

    ax2.boxplot([normal_data, anomaly_data], labels=['Normal', 'Anomaly'],
                patch_artist=True,
                boxprops=dict(facecolor='lightblue', color='blue'),
                medianprops=dict(color='red', linewidth=2),
                whiskerprops=dict(color='blue'),
                capprops=dict(color='blue'))

    ax2.set_title('Score Distribution by Classification', fontsize=14, fontweight='bold')
    ax2.set_ylabel('Anomaly Score', fontsize=12)
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('anomaly_distribution.png', dpi=300, bbox_inches='tight')
    plt.show()

def plot_feature_correlations(df):
    """Plot correlation between features and anomaly scores"""
    # Select numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    key_features = ['total_alerts', 'peak_severity', 'avg_severity', 'failed_logins_count',
                   'ssh_commands_count', 'scan_activity_count', 'malware_detections',
                   'unique_sources', 'unique_destinations', 'failed_login_ratio',
                   'unique_ip_ratio', 'alert_rate_ratio']

    available_features = [col for col in key_features if col in df.columns]
    available_features.append('anomaly_score')

    if len(available_features) > 1:
        corr_matrix = df[available_features].corr()

        plt.figure(figsize=(12, 10))
        sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', center=0,
                   square=True, linewidths=0.5, cbar_kws={"shrink": 0.8})

        plt.title('Feature Correlation with Anomaly Scores', fontsize=16, fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.savefig('feature_correlations.png', dpi=300, bbox_inches='tight')
        plt.show()

def plot_anomaly_summary(df):
    """Create a summary plot with key statistics"""
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))

    # Summary statistics
    stats_text = ".1f"".1f"".1f"".1f"f"""
    Total Samples: {len(df)}
    Anomalies Detected: {df['is_anomaly'].sum()} ({df['is_anomaly'].mean()*100:.1f}%)
    Mean Score: {df['anomaly_score'].mean():.3f}
    Score Std: {df['anomaly_score'].std():.3f}
    Score Range: {df['anomaly_score'].min():.3f} - {df['anomaly_score'].max():.3f}
    """

    ax1.text(0.1, 0.5, stats_text, transform=ax1.transAxes,
             fontsize=12, verticalalignment='center',
             bbox=dict(boxstyle="round,pad=0.3", facecolor="lightblue", alpha=0.5))
    ax1.set_title('Detection Summary', fontsize=14, fontweight='bold')
    ax1.axis('off')

    # Anomaly score percentiles
    percentiles = [1, 5, 10, 25, 50, 75, 90, 95, 99]
    percentile_values = np.percentile(df['anomaly_score'], percentiles)

    ax2.bar(range(len(percentiles)), percentile_values, alpha=0.7, color='skyblue', edgecolor='black')
    ax2.set_xticks(range(len(percentiles)))
    ax2.set_xticklabels([f'{p}%' for p in percentiles])
    ax2.set_title('Anomaly Score Percentiles', fontsize=14, fontweight='bold')
    ax2.set_ylabel('Score', fontsize=12)
    ax2.grid(True, alpha=0.3)

    # Host analysis
    if 'agent.ip' in df.columns:
        host_counts = df['agent.ip'].value_counts().head(10)
        host_counts.plot(kind='barh', ax=ax3, color='lightgreen', edgecolor='black')
        ax3.set_title('Samples by Host', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Count', fontsize=12)

    # Time analysis
    df['hour'] = df['timestamp'].dt.hour
    hourly_counts = df.groupby('hour').size()
    hourly_counts.plot(kind='bar', ax=ax4, color='orange', edgecolor='black', alpha=0.7)
    ax4.set_title('Samples by Hour of Day', fontsize=14, fontweight='bold')
    ax4.set_xlabel('Hour', fontsize=12)
    ax4.set_ylabel('Count', fontsize=12)
    ax4.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('anomaly_summary.png', dpi=300, bbox_inches='tight')
    plt.show()

def main():
    print("🔍 Loading anomaly validation results...")
    df = load_validation_results()

    if df is None:
        return

    print(f"✅ Loaded {len(df)} validation samples")
    print(f"📊 Anomaly detection rate: {df['is_anomaly'].mean()*100:.1f}%")

    print("\n📈 Generating visualizations...")

    # Create all plots
    plot_anomaly_scores_over_time(df)
    print("✅ Timeline plot saved as 'anomaly_timeline.png'")

    plot_score_distribution(df)
    print("✅ Distribution plot saved as 'anomaly_distribution.png'")

    plot_feature_correlations(df)
    print("✅ Correlation plot saved as 'feature_correlations.png'")

    plot_anomaly_summary(df)
    print("✅ Summary plot saved as 'anomaly_summary.png'")

    print("\n🎉 All visualizations complete!")
    print("Check the generated PNG files for detailed analysis.")

if __name__ == "__main__":
    main()