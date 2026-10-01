"""
Anomaly Separation Visualiser
==============================
Companion script for train_anomaly.py.

What it does
------------
1. Reads the same config / parquet / pickle as train_anomaly.py
2. Runs the full dataset (train + test) through the saved IsolationForest
3. Produces a 6-panel matplotlib figure that shows how well anomalies are
   separated from normal samples, then saves it to
   backend/data/reports/anomaly_separation.png

Run from the repo root:
    python backend/scripts/train_models/training_loops/visualize_anomaly.py
"""

import pickle
import logging
import warnings
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import yaml
from pathlib import Path
from sklearn.decomposition import PCA

warnings.filterwarnings("ignore")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ── resolved paths (mirrors train_anomaly.py) ────────────────────────────────
ROOT_DIR    = Path(__file__).resolve().parents[4]
CONFIG_PATH = ROOT_DIR / "backend/scripts/train_models/configs/scaling_config.yaml"

# ── dark-theme palette ────────────────────────────────────────────────────────
COL_NORMAL  = "#4FC3F7"   # sky-blue  → normal
COL_ANOMALY = "#EF5350"   # coral-red → anomaly
COL_THRESH  = "#FFA726"   # amber     → decision boundary
FIG_BG      = "#0D1117"
AX_BG       = "#161B22"
TEXT_COL    = "#E6EDF3"


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


# ── helpers ───────────────────────────────────────────────────────────────────
def _style(ax, title: str) -> None:
    """Apply consistent dark-theme styling to a matplotlib axis."""
    ax.set_facecolor(AX_BG)
    ax.set_title(title, color=TEXT_COL, fontsize=12, fontweight="bold")
    ax.tick_params(colors=TEXT_COL)
    ax.xaxis.label.set_color(TEXT_COL)
    ax.yaxis.label.set_color(TEXT_COL)
    ax.grid(True, alpha=0.2, color=TEXT_COL)
    ax.yaxis.label.set_color(TEXT_COL)


def _legend(ax) -> None:
    leg = ax.legend(fontsize=8, facecolor=AX_BG, edgecolor="#30363D")
    for txt in leg.get_texts():
        txt.set_color(TEXT_COL)


# ── load config + data + model ────────────────────────────────────────────────
def load_artifacts():
    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)

    features_dir = ROOT_DIR / "backend/data/features/v1"
    models_dir   = ROOT_DIR / config["paths"]["models_out"]

    data_file  = features_dir / "behavioral_features_24h.parquet"
    model_file = models_dir   / "anomaly_detector.pkl"

    if not data_file.exists():
        raise FileNotFoundError(
            f"Feature parquet not found: {data_file}\n"
            "Run the data-engineering pipeline then train_anomaly.py first."
        )
    if not model_file.exists():
        raise FileNotFoundError(
            f"Trained model not found: {model_file}\n"
            "Run train_anomaly.py first."
        )

    logger.info(f"Loading parquet: {data_file}")
    df = pd.read_parquet(data_file)

    logger.info(f"Loading model:   {model_file}")
    with open(model_file, "rb") as f:
        save_data = pickle.load(f)

    return df, save_data, config


# ── score the full dataset ────────────────────────────────────────────────────
def score_dataset(df: pd.DataFrame, save_data: dict):
    """
    Replicates the exact same feature-selection logic as train_anomaly.py:
      - sort by timestamp
      - extract 48 features from each row
      - transform with the saved scaler
    Returns (X_raw, X_scaled, scores, preds, feature_names, split_idx)
    """
    model         = save_data["model"]
    scaler        = save_data["scaler"]
    feature_names = save_data["feature_names"]

    df = df.sort_values(by="timestamp", ignore_index=True)
    split_idx = int(len(df) * 0.8)

    # Extract 48 features from each row
    logger.info("Extracting 48 features from dataset...")
    features = []
    for _, row in df.iterrows():
        feat = extract_48_features(row)
        features.append(feat)
    
    X_raw = np.array(features)

    logger.info(f"Feature matrix shape: {X_raw.shape}")
    X_scaled = scaler.transform(X_raw)

    scores = model.score_samples(X_scaled)   # lower = more anomalous
    preds  = model.predict(X_scaled)         # -1 = anomaly, +1 = normal

    n_anom = (preds == -1).sum()
    logger.info(f"Normal: {(preds==1).sum():,}  |  Anomaly: {n_anom:,}  "
                f"({n_anom / len(preds) * 100:.2f}%)")

    return X_raw, X_scaled, scores, preds, feature_names, split_idx


# ── the six panels ────────────────────────────────────────────────────────────

def panel_score_histogram(ax, scores, preds):
    """Score distribution – are the two populations clearly separated?"""
    normal_s  = scores[preds ==  1]
    anomaly_s = scores[preds == -1]
    bins = np.linspace(scores.min(), scores.max(), 60)

    ax.hist(normal_s,  bins=bins, color=COL_NORMAL,  alpha=0.75,
            label=f"Normal  ({len(normal_s):,})",  edgecolor="none")
    ax.hist(anomaly_s, bins=bins, color=COL_ANOMALY, alpha=0.85,
            label=f"Anomaly ({len(anomaly_s):,})", edgecolor="none")

    # Isolation Forest decision score is at the contamination quantile
    thresh = np.quantile(scores, 0.01)   # approx threshold line
    ax.axvline(thresh, color=COL_THRESH, linewidth=1.5, linestyle="--",
               label=f"Approx threshold")

    ax.set_xlabel("IF score_samples()  (lower = more anomalous)")
    ax.set_ylabel("Count")
    _legend(ax)
    _style(ax, "Score Distribution — Normal vs Anomaly")


def panel_pca_scatter(ax, X_scaled, preds):
    """2-D PCA scatter — visually shows cluster separation."""
    pca = PCA(n_components=2, random_state=42)
    X2  = pca.fit_transform(X_scaled)
    var = pca.explained_variance_ratio_

    mask_n = preds ==  1
    mask_a = preds == -1

    ax.scatter(X2[mask_n, 0], X2[mask_n, 1],
               c=COL_NORMAL,  s=7,  alpha=0.35, linewidths=0, label="Normal")
    ax.scatter(X2[mask_a, 0], X2[mask_a, 1],
               c=COL_ANOMALY, s=12, alpha=0.80, linewidths=0, label="Anomaly")

    ax.set_xlabel(f"PC1 ({var[0]*100:.1f}% variance)")
    ax.set_ylabel(f"PC2 ({var[1]*100:.1f}% variance)")
    _legend(ax)
    _style(ax, "PCA 2-D Projection")


def panel_boxplot(ax, scores, preds):
    """Box-plot showing the spread of IF scores by class."""
    normal_s  = scores[preds ==  1]
    anomaly_s = scores[preds == -1]

    bp = ax.boxplot(
        [normal_s, anomaly_s],
        labels=["Normal", "Anomaly"],
        patch_artist=True,
        widths=0.4,
        medianprops  =dict(color=TEXT_COL, linewidth=2),
        whiskerprops =dict(color=TEXT_COL),
        capprops     =dict(color=TEXT_COL),
        flierprops   =dict(marker=".", color=COL_THRESH, alpha=0.4, markersize=3),
    )
    bp["boxes"][0].set_facecolor(COL_NORMAL)
    bp["boxes"][1].set_facecolor(COL_ANOMALY)
    for box in bp["boxes"]:
        box.set_alpha(0.75)

    ax.set_ylabel("IF score_samples()")
    _style(ax, "Score Box-plot by Class")


def panel_feature_diff(ax, X_raw, preds, feature_names):
    """
    Bar-chart of |mean(anomaly) − mean(normal)| per feature — shows which
    features drive the separation most.
    """
    mask_n = preds ==  1
    mask_a = preds == -1

    if mask_a.sum() == 0:
        ax.text(0.5, 0.5, "No anomalies detected", transform=ax.transAxes,
                ha="center", va="center", color=TEXT_COL, fontsize=10)
        _style(ax, "Feature Contribution to Separation")
        return

    diff   = np.abs(X_raw[mask_a].mean(axis=0) - X_raw[mask_n].mean(axis=0))
    order  = np.argsort(diff)
    colors = [COL_ANOMALY if d > diff.mean() else COL_NORMAL for d in diff[order]]
    names  = [feature_names[i] for i in order]

    ax.barh(range(len(order)), diff[order], color=colors, alpha=0.80, edgecolor="none")
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels(names, fontsize=7)
    ax.set_xlabel("|Mean anomaly − Mean normal|  (raw scale)")
    _style(ax, "Feature Contribution to Separation")


def panel_train_test_split(ax, scores, preds, split_idx):
    """Score per sample index, with the train/test split line."""
    idx_n = np.where(preds ==  1)[0]
    idx_a = np.where(preds == -1)[0]

    ax.scatter(idx_n, scores[idx_n], c=COL_NORMAL,  s=4, alpha=0.3,
               linewidths=0, label="Normal")
    ax.scatter(idx_a, scores[idx_a], c=COL_ANOMALY, s=7, alpha=0.7,
               linewidths=0, label="Anomaly")
    ax.axvline(split_idx, color="#A371F7", linewidth=1.4, linestyle="--",
               label=f"Train/Test split (idx {split_idx:,})")

    ax.set_xlabel("Sample index (timestamp-sorted)")
    ax.set_ylabel("IF score_samples()")
    _legend(ax)
    _style(ax, "Score Timeline — Train vs Test split")


def panel_cumulative_rate(ax, scores, preds, split_idx):
    """Cumulative anomaly rate across samples (train vs test zones)."""
    n = len(preds)
    cumulative = np.cumsum(preds == -1) / (np.arange(n) + 1) * 100

    ax.plot(cumulative, color=COL_ANOMALY, linewidth=1.5,
            label="Cumulative anomaly %")
    ax.fill_between(range(n), cumulative, alpha=0.12, color=COL_ANOMALY)
    ax.axvline(split_idx, color="#A371F7", linewidth=1.4, linestyle="--",
               label=f"Train/Test split")
    ax.axhline(cumulative[-1], color=COL_THRESH, linewidth=1, linestyle=":",
               label=f"Final rate: {cumulative[-1]:.2f}%")

    ax.set_xlabel("Sample index")
    ax.set_ylabel("Cumulative Anomaly Rate (%)")
    _legend(ax)
    _style(ax, "Cumulative Anomaly Rate")


# ── assemble & save ───────────────────────────────────────────────────────────
def build_figure(df, save_data, config):
    X_raw, X_scaled, scores, preds, feature_names, split_idx = score_dataset(
        df, save_data
    )

    matplotlib.rcParams["font.family"] = "DejaVu Sans"
    fig = plt.figure(figsize=(18, 11), facecolor=FIG_BG)

    contamination = config["training"]["anomaly_detector"]["contamination"]
    n_est         = config["training"]["anomaly_detector"]["n_estimators"]
    n_anomaly     = (preds == -1).sum()

    fig.suptitle(
        f"IsolationForest Anomaly Separation Report  "
        f"[n_estimators={n_est}, contamination={contamination}]",
        fontsize=13, fontweight="bold", color=TEXT_COL, y=0.99,
    )

    gs = gridspec.GridSpec(
        2, 3, figure=fig, hspace=0.44, wspace=0.35,
        left=0.06, right=0.97, top=0.93, bottom=0.07,
    )
    axes = [fig.add_subplot(gs[r, c]) for r in range(2) for c in range(3)]

    panel_score_histogram  (axes[0], scores, preds)
    panel_pca_scatter      (axes[1], X_scaled, preds)
    panel_boxplot          (axes[2], scores, preds)
    panel_feature_diff     (axes[3], X_raw, preds, feature_names)
    panel_train_test_split (axes[4], scores, preds, split_idx)
    panel_cumulative_rate  (axes[5], scores, preds, split_idx)

    summary = (
        f"Total samples: {len(preds):,}  |  "
        f"Normal: {(preds==1).sum():,}  |  "
        f"Anomaly: {n_anomaly:,}  |  "
        f"Rate: {n_anomaly/len(preds)*100:.2f}%  |  "
        f"Features: {len(feature_names)}"
    )
    fig.text(0.5, 0.003, summary, ha="center", fontsize=8.5,
             color="#8B949E", style="italic")

    out_dir  = ROOT_DIR / "backend/data/reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "anomaly_separation.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=FIG_BG)
    logger.info(f"Figure saved → {out_path}")
    plt.show()


# ── entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    df, save_data, config = load_artifacts()
    build_figure(df, save_data, config)
