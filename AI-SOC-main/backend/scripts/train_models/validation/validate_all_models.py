"""
Unified Model Validation Script
================================
Validates all 3 trained ML models in one run:
  1. Anomaly Detector   (IsolationForest)
  2. Attack Forecaster  (ExponentialSmoothing)
  3. LSTM Stage Predictor (Keras LSTM)

Run from project root:
  python backend/scripts/train_models/validation/validate_all_models.py
"""

import logging
import yaml
import pickle
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress TensorFlow noise
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

ROOT_DIR = Path(__file__).resolve().parents[4]


def _header(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def _subheader(title: str):
    print(f"\n{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50)")


# ══════════════════════════════════════════════════════════════════════
# 1. ANOMALY DETECTOR
# ══════════════════════════════════════════════════════════════════════

def validate_anomaly_detector(models_dir: Path, features_dir: Path) -> dict:
    _header("MODEL 1: ANOMALY DETECTOR (IsolationForest)")

    model_path = models_dir / "anomaly_detector.pkl"
    data_path = features_dir / "behavioral_features_24h.parquet"

    if not model_path.exists():
        print("  ❌ anomaly_detector.pkl NOT FOUND — skipping")
        return {"status": "missing"}
    if not data_path.exists():
        print("  ❌ behavioral_features_24h.parquet NOT FOUND — skipping")
        return {"status": "missing"}

    with open(model_path, "rb") as f:
        artifact = pickle.load(f)

    model = artifact["model"]
    scaler = artifact["scaler"]
    feature_names = artifact["feature_names"]

    df = pd.read_parquet(data_path)
    df = df.sort_values(by="timestamp").reset_index(drop=True)

    split_idx = int(len(df) * 0.8)
    holdout = df.iloc[split_idx:].copy()

    if len(holdout) == 0:
        print("  ⚠️  Holdout set is empty")
        return {"status": "empty_holdout"}

    available = [f for f in feature_names if f in holdout.columns]
    X = holdout[available].fillna(0)
    X_scaled = scaler.transform(X)

    scores = model.decision_function(X_scaled)
    preds = model.predict(X_scaled)

    n_anom = (preds == -1).sum()
    anomaly_pct = (n_anom / len(preds)) * 100

    _subheader("Model Info")
    print(f"  Features trained on:  {len(feature_names)}")
    print(f"  Feature names:        {feature_names}")
    print(f"  N estimators:         {model.n_estimators}")
    print(f"  Contamination:        {model.contamination}")

    _subheader("Holdout Results (last 20%)")
    print(f"  Holdout rows:         {len(holdout)}")
    print(f"  Anomalies detected:   {n_anom} ({anomaly_pct:.1f}%)")
    print(f"  Normal traffic:       {len(preds) - n_anom} ({100 - anomaly_pct:.1f}%)")

    _subheader("Score Distribution")
    print(f"  Mean:   {scores.mean():.4f}")
    print(f"  Std:    {scores.std():.4f}")
    print(f"  Min:    {scores.min():.4f}  (most anomalous)")
    print(f"  Max:    {scores.max():.4f}  (most normal)")

    _subheader("Top 5 Most Anomalous Windows")
    holdout["anomaly_score"] = scores
    top = holdout.nsmallest(5, "anomaly_score")
    cols = ["timestamp", "agent.ip", "anomaly_score"]
    cols += [c for c in ["total_alerts", "peak_severity", "failed_logins_count"] if c in top.columns]
    print(top[[c for c in cols if c in top.columns]].to_string(index=False))

    # Histogram
    _subheader("Score Histogram")
    bins = np.linspace(scores.min(), scores.max(), 11)
    hist, edges = np.histogram(scores, bins=bins)
    mx = max(hist) if max(hist) > 0 else 1
    for i in range(len(hist)):
        bar = "█" * int((hist[i] / mx) * 30)
        print(f"  [{edges[i]:+.3f}, {edges[i+1]:+.3f}) | {bar} ({hist[i]})")

    return {
        "status": "ok", "holdout_rows": len(holdout),
        "anomalies": int(n_anom), "anomaly_pct": round(anomaly_pct, 1),
        "mean_score": round(float(scores.mean()), 4)
    }


# ══════════════════════════════════════════════════════════════════════
# 2. ATTACK FORECASTER
# ══════════════════════════════════════════════════════════════════════

def validate_forecaster(models_dir: Path, features_dir: Path) -> dict:
    _header("MODEL 2: ATTACK FORECASTER (ExponentialSmoothing)")

    model_path = models_dir / "attack_forecaster.pkl"
    if not model_path.exists():
        print("  ❌ attack_forecaster.pkl NOT FOUND — skipping")
        return {"status": "missing"}

    with open(model_path, "rb") as f:
        artifact = pickle.load(f)

    _subheader("Model Info")
    print(f"  Model type:     {artifact['best_params']['model']}")
    print(f"  Train range:    {artifact.get('train_start_date')} → {artifact.get('train_end_date')}")
    print(f"  Tactic models:  {len(artifact.get('tactic_models', {}))} categories")

    model_fit = artifact.get("model_fit")
    if model_fit is None:
        print("  ⚠️  Flat mean model (insufficient seasonal data for ExponentialSmoothing)")
        return {"status": "flat_model"}

    _subheader("24-Hour Forecast (next 24 hourly windows)")
    try:
        forecast = model_fit.forecast(24)
        print(forecast.to_string())

        _subheader("Forecast Statistics")
        print(f"  Mean predicted alerts/hour:  {forecast.mean():.2f}")
        print(f"  Min:                         {forecast.min():.2f}")
        print(f"  Max:                         {forecast.max():.2f}")
        print(f"  Total predicted (24h):       {forecast.sum():.0f}")

        return {
            "status": "ok",
            "forecast_mean": round(float(forecast.mean()), 2),
            "forecast_total_24h": round(float(forecast.sum()), 0)
        }
    except Exception as e:
        print(f"  ❌ Forecast failed: {e}")
        return {"status": "error", "error": str(e)}


# ══════════════════════════════════════════════════════════════════════
# 3. LSTM ATTACK STAGE PREDICTOR
# ══════════════════════════════════════════════════════════════════════

STAGE_NAMES = {
    0: "unknown", 1: "reconnaissance", 2: "resource_development",
    3: "initial_access", 4: "execution", 5: "persistence",
    6: "privilege_escalation", 7: "defense_evasion", 8: "credential_access",
    9: "discovery", 10: "lateral_movement", 11: "collection",
    12: "command_and_control", 13: "exfiltration", 14: "impact"
}

def validate_lstm(models_dir: Path, features_dir: Path) -> dict:
    _header("MODEL 3: LSTM ATTACK STAGE PREDICTOR")

    h5_path = models_dir / "attack_stage_lstm.h5"
    scaler_path = models_dir / "attack_stage_lstm_scaler.pkl"
    seq_path = features_dir / "sequence_features.parquet"

    if not h5_path.exists():
        print("  ❌ attack_stage_lstm.h5 NOT FOUND — skipping")
        return {"status": "missing"}

    try:
        from keras.models import load_model
    except ImportError:
        print("  ❌ TensorFlow/Keras not installed — skipping")
        return {"status": "no_tensorflow"}

    model = load_model(h5_path)

    _subheader("Model Architecture")
    model.summary(print_fn=lambda x: print(f"  {x}"))

    total_params = model.count_params()
    print(f"\n  Total parameters: {total_params:,}")

    if not scaler_path.exists():
        print("  ⚠️  Scaler not found, skipping inference test")
        return {"status": "ok_no_scaler", "params": total_params}

    scaler = joblib.load(scaler_path)

    if not seq_path.exists():
        print("  ⚠️  sequence_features.parquet not found, skipping holdout scoring")
        return {"status": "ok_no_data", "params": total_params}

    _subheader("Holdout Evaluation")
    df = pd.read_parquet(seq_path)

    if "timestamp" in df.columns:
        df = df.sort_values("timestamp").reset_index(drop=True)

    split_idx = int(len(df) * 0.8)
    holdout = df.iloc[split_idx:]
    print(f"  Total sequences:   {len(df)}")
    print(f"  Holdout sequences: {len(holdout)}")

    if len(holdout) == 0:
        return {"status": "empty_holdout", "params": total_params}

    # Prepare tensors
    seq_len = 50  # from config
    num_features = 25
    X_list, y_true = [], []

    for _, row in holdout.iterrows():
        seq = row["sequence_features"]
        padded = []
        for step in seq:
            s = list(step)
            while len(s) < num_features:
                s.append(0.0)
            padded.append(s[:num_features])
        while len(padded) < seq_len:
            padded.insert(0, [0.0] * num_features)
        X_list.append(padded[-seq_len:])
        y_true.append(row["target_stage"])

    X = np.array(X_list, dtype=np.float32)
    y_true = np.array(y_true, dtype=np.int32)

    X_flat = scaler.transform(X.reshape(-1, num_features))
    X_scaled = X_flat.reshape(-1, seq_len, num_features)

    preds_proba = model.predict(X_scaled, verbose=0)
    preds = preds_proba.argmax(axis=1)

    accuracy = (preds == y_true).mean() * 100
    print(f"\n  Holdout Accuracy:  {accuracy:.2f}%")

    _subheader("Per-Stage Accuracy")
    from collections import Counter
    stage_correct = Counter()
    stage_total = Counter()
    for true, pred in zip(y_true, preds):
        stage_total[true] += 1
        if true == pred:
            stage_correct[true] += 1

    print(f"  {'Stage':<25s} {'Correct':>8s} {'Total':>8s} {'Accuracy':>10s}")
    print(f"  {'─' * 55}")
    for stage_id in sorted(stage_total.keys()):
        name = STAGE_NAMES.get(stage_id, f"stage_{stage_id}")
        correct = stage_correct[stage_id]
        total = stage_total[stage_id]
        acc = (correct / total * 100) if total > 0 else 0
        print(f"  {name:<25s} {correct:>8d} {total:>8d} {acc:>9.1f}%")

    _subheader("Prediction Distribution")
    pred_counts = Counter(preds)
    for stage_id in sorted(pred_counts.keys()):
        name = STAGE_NAMES.get(stage_id, f"stage_{stage_id}")
        count = pred_counts[stage_id]
        bar = "█" * int((count / len(preds)) * 40)
        print(f"  {name:<25s} {bar} ({count})")

    _subheader("Confidence Distribution")
    max_confidences = preds_proba.max(axis=1)
    print(f"  Mean confidence:  {max_confidences.mean():.4f}")
    print(f"  Min confidence:   {max_confidences.min():.4f}")
    print(f"  Max confidence:   {max_confidences.max():.4f}")

    return {
        "status": "ok", "params": total_params,
        "holdout_accuracy": round(accuracy, 2),
        "mean_confidence": round(float(max_confidences.mean()), 4)
    }


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

def main():
    with open(ROOT_DIR / "backend/scripts/train_models/configs/scaling_config.yaml") as f:
        config = yaml.safe_load(f)

    models_dir = ROOT_DIR / config["paths"]["models_out"]
    features_dir = ROOT_DIR / "backend/data/features/v1"

    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + "  AI-SOC — UNIFIED MODEL VALIDATION REPORT".center(68) + "║")
    print("║" + f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(68) + "║")
    print("╚" + "═" * 68 + "╝")

    results = {}
    results["anomaly_detector"] = validate_anomaly_detector(models_dir, features_dir)
    results["attack_forecaster"] = validate_forecaster(models_dir, features_dir)
    results["lstm_stage_predictor"] = validate_lstm(models_dir, features_dir)

    # Final Summary
    _header("SUMMARY")
    for name, res in results.items():
        status = res.get("status", "unknown")
        icon = "✅" if status == "ok" else "⚠️" if "missing" not in status else "❌"
        detail = ""
        if "holdout_accuracy" in res:
            detail = f"  Accuracy: {res['holdout_accuracy']}%"
        elif "anomaly_pct" in res:
            detail = f"  Anomalies: {res['anomaly_pct']}%"
        elif "forecast_mean" in res:
            detail = f"  Mean: {res['forecast_mean']} alerts/hr"
        print(f"  {icon} {name:<25s} [{status}]{detail}")

    print("\n" + "=" * 70)
    print("  VALIDATION COMPLETE")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
