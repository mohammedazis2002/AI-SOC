"""
Anomaly Detector Validation Script
===================================
Loads the trained IsolationForest from backend/models/anomaly_detector.pkl
and evaluates it against the holdout 20% of the behavioral feature store.

Outputs:
  - Anomaly score distribution (mean, std, min, max)
  - Percentage of data flagged as anomalous
  - Top 10 most anomalous time windows with their feature values
  - Score histogram saved as anomaly_score_distribution.csv
"""

import logging
import yaml
import pickle
import pandas as pd
import numpy as np
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_48_features(row):
    """Extract all 48 features from an aggregated behavioral features row"""
    
    # Parse timestamp
    timestamp = pd.to_datetime(row['timestamp'])
    
    # TEMPORAL FEATURES (6)
    temporal = [
        float(timestamp.hour),  # hour_of_day
        float(timestamp.weekday()),  # day_of_week
        float(timestamp.weekday() >= 5),  # is_weekend
        float(9 <= timestamp.hour <= 17),  # is_business_hours
        0.0,  # time_since_last (not available)
        0.0   # freq_last_hour (not available)
    ]
    
    # RULE-BASED FEATURES (8)
    severity = row.get('avg_severity', 5)
    total_alerts = row.get('total_alerts', 0)
    failed_logins = row.get('failed_logins_count', 0)
    ssh_commands = row.get('ssh_commands_count', 0)
    scan_activity = row.get('scan_activity_count', 0)
    malware = row.get('malware_detections', 0)
    
    rule_based = [
        float(severity),
        0.0,  # num_groups (not available)
        1.0 if scan_activity > 0 or malware > 0 else 0.0,  # num_mitre
        float(failed_logins > 0),  # is_auth
        float(ssh_commands > 0),  # is_priv
        0.0,  # is_pci
        0.0,  # is_nist
        0.0  # has_cve
    ]
    
    # NETWORK FEATURES (8)
    network = [
        0.5,  # src_ip (default)
        0.0,  # src_port
        0.5,  # dst_ip (default)
        0.0,  # dst_port
        0.0,  # protocol
        0.0,  # bytes_sent
        0.0,  # bytes_received
        0.0   # session_duration
    ]
    
    # USER/ASSET FEATURES (8)
    agent_ip = str(row.get('agent.ip', '0.0.0.0'))
    
    def string_to_hash(s):
        return (hash(str(s)) % 10000) / 10000.0
    
    def is_external_ip(ip):
        try:
            parts = [int(p) for p in ip.split('.')]
            if parts[0] == 10: return 0
            if parts[0] == 172 and 16 <= parts[1] <= 31: return 0
            if parts[0] == 192 and parts[1] == 168: return 0
            return 1
        except:
            return 0
    
    user_asset = [
        0.0,  # user_hash
        string_to_hash(agent_ip),
        0.5,  # asset_crit
        0.3,  # user_privilege_level
        0.0,  # uses_sudo
        float(is_external_ip(agent_ip)),
        0.5,  # risk_score
        0.0   # is_known_good_ip
    ]
    
    # CONTEXT FEATURES (10)
    context = [
        float(total_alerts / 24.0),  # sim_1h (approx)
        float(total_alerts),  # sim_1d
        1.0,  # correlation_group_size
        0.0,  # first_seen
        0.0,  # hist_fp_rate
        0.5,  # vt_reputation_score
        float(malware > 0),  # threat_intel_match
        0.0,  # has_sensitive_data
        0.0,  # in_maintenance_window
        0.0   # compliance_violation
    ]
    
    # BEHAVIORAL FEATURES (8)
    failed_login_ratio = row.get('failed_login_ratio', 0)
    unique_ip_ratio = row.get('unique_ip_ratio', 0)
    alert_rate_ratio = row.get('alert_rate_ratio', 0)
    
    behavioral = [
        float(failed_login_ratio),  # user_dev
        float(unique_ip_ratio),  # asset_dev
        0.0,  # unusual_time
        0.0,  # unusual_loc
        float(alert_rate_ratio),  # unusual_action
        0.0,  # unusual_tgt
        float(total_alerts > 100),  # unusual_vol
        0.0   # pattern_break
    ]
    
    # Combine all 48 features
    return temporal + rule_based + network + user_asset + context + behavioral


def validate_anomaly_detector(config_path="backend/scripts/train_models/configs/scaling_config.yaml"):
    root_dir = Path(__file__).resolve().parents[4]
    
    with open(root_dir / config_path, "r") as f:
        config = yaml.safe_load(f)
    
    # ── 1. Load the trained artifact ──────────────────────────────────────
    models_dir = root_dir / config["paths"]["models_out"]
    model_path = models_dir / "anomaly_detector.pkl"
    
    if not model_path.exists():
        logger.error(f"Model artifact not found at {model_path}. Run train_anomaly.py first.")
        return
    
    with open(model_path, "rb") as f:
        artifact = pickle.load(f)
    
    model = artifact["model"]
    scaler = artifact["scaler"]
    feature_names = artifact["feature_names"]
    
    logger.info(f"Loaded IsolationForest artifact with {len(feature_names)} features:")
    logger.info(f"  Features: {feature_names}")
    
    # ── 2. Load the holdout data (last 20% by time) ──────────────────────
    features_dir = root_dir / "backend/data/features/v1"
    data_file = features_dir / "behavioral_features_24h.parquet"
    
    if not data_file.exists():
        logger.error(f"Feature store not found at {data_file}. Run b_feature_builder.py first.")
        return
    
    df = pd.read_parquet(data_file)
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    
    split_idx = int(len(df) * 0.8)
    holdout_df = df.iloc[split_idx:].copy()
    
    logger.info(f"Total feature rows: {len(df)}")
    logger.info(f"Training set (first 80%): {split_idx} rows")
    logger.info(f"Holdout set (last 20%): {len(holdout_df)} rows")
    
    if len(holdout_df) == 0:
        logger.warning("Holdout set is empty. Need more data for validation.")
        return
    
    # ── 3. Extract 48 features from holdout data ──────────────────────────
    logger.info("Extracting 48 features from holdout data...")
    features = []
    for _, row in holdout_df.iterrows():
        feat = extract_48_features(row)
        features.append(feat)
    
    X_holdout = pd.DataFrame(features)
    X_scaled = scaler.transform(X_holdout)
    
    # ── 4. Generate anomaly scores ────────────────────────────────────────
    # decision_function: negative = more anomalous, positive = more normal
    raw_scores = model.decision_function(X_scaled)
    # predict: -1 = anomaly, 1 = normal
    predictions = model.predict(X_scaled)
    
    holdout_df["anomaly_score"] = raw_scores
    holdout_df["is_anomaly"] = (predictions == -1).astype(int)
    
    # ── 5. Statistical Summary ────────────────────────────────────────────
    n_anomalies = (predictions == -1).sum()
    n_normal = (predictions == 1).sum()
    anomaly_pct = (n_anomalies / len(predictions)) * 100
    
    print("\n" + "=" * 70)
    print("  ANOMALY DETECTOR VALIDATION REPORT")
    print("=" * 70)
    
    print(f"\n📊 Dataset Summary:")
    print(f"   Holdout rows evaluated:  {len(holdout_df)}")
    print(f"   Features used:           48")
    
    print(f"\n🔍 Anomaly Score Distribution:")
    print(f"   Mean score:   {raw_scores.mean():.4f}")
    print(f"   Std dev:      {raw_scores.std():.4f}")
    print(f"   Min (most anomalous):  {raw_scores.min():.4f}")
    print(f"   Max (most normal):     {raw_scores.max():.4f}")
    
    print(f"\n🚨 Detection Results:")
    print(f"   Anomalies detected:  {n_anomalies} ({anomaly_pct:.1f}%)")
    print(f"   Normal traffic:      {n_normal} ({100 - anomaly_pct:.1f}%)")
    
    # ── 6. Top 10 Most Anomalous Windows ──────────────────────────────────
    top_anomalies = holdout_df.nsmallest(10, "anomaly_score")
    
    print(f"\n🔥 Top 10 Most Anomalous Time Windows:")
    print("-" * 70)
    
    display_cols = ["timestamp", "agent.ip", "anomaly_score", "is_anomaly"]
    # Add a few key feature columns if they exist
    for col in ["total_alerts", "peak_severity", "failed_logins_count", "unique_sources"]:
        if col in top_anomalies.columns:
            display_cols.append(col)
    
    display_cols = [c for c in display_cols if c in top_anomalies.columns]
    print(top_anomalies[display_cols].to_string(index=False))
    
    # ── 7. Score Distribution Histogram (binned) ──────────────────────────
    bins = np.linspace(raw_scores.min(), raw_scores.max(), 21)
    hist, bin_edges = np.histogram(raw_scores, bins=bins)
    
    print(f"\n📈 Score Distribution Histogram:")
    max_bar = max(hist) if max(hist) > 0 else 1
    for i in range(len(hist)):
        bar_len = int((hist[i] / max_bar) * 40)
        label = f"  [{bin_edges[i]:+.3f}, {bin_edges[i+1]:+.3f})"
        print(f"  {label:>30s} | {'█' * bar_len} ({hist[i]})")
    
    # ── 8. Export detailed results ────────────────────────────────────────
    out_dir = root_dir / "backend/data/features/v1"
    results_file = out_dir / "anomaly_validation_results.csv"
    holdout_df.to_csv(results_file, index=False)
    logger.info(f"\nDetailed results exported to: {results_file}")
    
    print("\n" + "=" * 70)
    print("  VALIDATION COMPLETE")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    validate_anomaly_detector()
