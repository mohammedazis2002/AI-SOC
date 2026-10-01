import logging
import yaml
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for saving plots
import matplotlib.pyplot as plt
from statsmodels.graphics.tsaplots import plot_acf, plot_pacf
from statsmodels.tsa.stattools import adfuller

import sys
sys.path.append(str(Path(__file__).resolve().parents[4]))

from backend.services.ml.attack_forecasting.attack_forecaster import MultivariateForecast

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# All 15 MITRE ATT&CK tactic columns (matching feature builder output)
TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access',
    'execution', 'persistence', 'privilege_escalation',
    'defense_evasion', 'credential_access', 'discovery',
    'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact', 'unknown'
]


def run_stationarity_test(series: pd.Series, name: str) -> dict:
    """Run Augmented Dickey-Fuller test to check stationarity and infer d."""
    result = adfuller(series.dropna(), autolag='AIC')
    adf_stat, p_value = result[0], result[1]
    is_stationary = p_value < 0.05
    
    logger.info(f"  ADF Test ({name}): statistic={adf_stat:.4f}, p-value={p_value:.4f} "
                f"→ {'Stationary ✅' if is_stationary else 'Non-stationary ❌ (differencing needed)'}")
    
    return {
        'adf_statistic': adf_stat,
        'p_value': p_value,
        'is_stationary': is_stationary
    }


def generate_acf_pacf_plots(series: pd.Series, diagnostics_dir: Path, tag: str):
    """Generate and save ACF/PACF diagnostic plots for parameter validation."""
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    nlags = min(72, len(series) // 2 - 1)  # Up to 3 days of lags, capped by series length
    if nlags < 10:
        logger.warning(f"Insufficient data for meaningful ACF/PACF plots (nlags={nlags})")
        return
    
    # ---- Plot 1: Raw series ACF/PACF ----
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle(f'ACF/PACF Diagnostics — {tag}', fontsize=14, fontweight='bold')
    
    # Raw series
    plot_acf(series.dropna(), ax=axes[0, 0], lags=nlags, title='ACF (Raw Series)')
    plot_pacf(series.dropna(), ax=axes[0, 1], lags=nlags, title='PACF (Raw Series)', method='ywm')
    
    # First-differenced series (to validate d parameter)
    diff_series = series.diff().dropna()
    if len(diff_series) > nlags + 1:
        plot_acf(diff_series, ax=axes[1, 0], lags=nlags, title='ACF (1st Differenced)')
        plot_pacf(diff_series, ax=axes[1, 1], lags=nlags, title='PACF (1st Differenced)', method='ywm')
    else:
        axes[1, 0].text(0.5, 0.5, 'Insufficient data after differencing', 
                        ha='center', va='center', transform=axes[1, 0].transAxes)
        axes[1, 1].text(0.5, 0.5, 'Insufficient data after differencing',
                        ha='center', va='center', transform=axes[1, 1].transAxes)
    
    for ax_row in axes:
        for ax in ax_row:
            ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    out_path = diagnostics_dir / f"acf_pacf_{tag}_{timestamp_str}.png"
    fig.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    logger.info(f"  ACF/PACF plot saved → {out_path}")
    
    # ---- Plot 2: Time series visualization ----
    fig2, axes2 = plt.subplots(2, 1, figsize=(16, 8))
    fig2.suptitle(f'Time Series Overview — {tag}', fontsize=14, fontweight='bold')
    
    axes2[0].plot(series.index, series.values, linewidth=0.6, color='#2196F3')
    axes2[0].set_title('Raw Total Alerts (Hourly)')
    axes2[0].set_ylabel('Alert Count')
    axes2[0].grid(True, alpha=0.3)
    
    # Rolling mean to show trend
    rolling_window = min(24, len(series) // 4)
    if rolling_window >= 2:
        rolling_mean = series.rolling(window=rolling_window).mean()
        axes2[0].plot(series.index, rolling_mean, linewidth=2, color='#FF5722', 
                      label=f'{rolling_window}h Rolling Mean')
        axes2[0].legend()
    
    axes2[1].plot(diff_series.index, diff_series.values, linewidth=0.6, color='#4CAF50')
    axes2[1].set_title('First Differenced Series')
    axes2[1].set_ylabel('Δ Alert Count')
    axes2[1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    ts_path = diagnostics_dir / f"timeseries_overview_{tag}_{timestamp_str}.png"
    fig2.savefig(ts_path, dpi=150, bbox_inches='tight')
    plt.close(fig2)
    logger.info(f"  Time series plot saved → {ts_path}")


def train_forecaster(config_path="backend/scripts/train_models/configs/scaling_config.yaml"):
    root_dir = Path(__file__).resolve().parents[4]
    
    with open(root_dir / config_path, "r") as f:
        config = yaml.safe_load(f)
        
    features_dir = root_dir / "backend/data/features/v1"
    models_dir = root_dir / config["paths"]["models_out"]
    models_dir.mkdir(parents=True, exist_ok=True)
    diagnostics_dir = models_dir / "diagnostics"
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    
    data_file = features_dir / "behavioral_features_1h.parquet"
    if not data_file.exists():
        logger.warning(f"Missing {data_file}. Run pipeline stages a and b first.")
        return
        
    # ─── 1. LOAD AND PREPARE DATA ───────────────────────────────────────
    logger.info("Loading 1h feature parquet...")
    df = pd.read_parquet(data_file)
    logger.info(f"Loaded {len(df)} rows, columns: {list(df.columns)}")
    
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Aggregate across all agents per hour → single time series
    agg_dict = {'total_alerts': 'sum'}
    for tactic in TACTICS:
        if tactic in df.columns:
            agg_dict[tactic] = 'sum'
        else:
            logger.warning(f"Tactic column '{tactic}' missing from parquet — will be zero-filled")
    
    hourly_df = df.groupby('timestamp').agg(agg_dict).reset_index()
    
    # Zero-fill any missing tactic columns
    for tactic in TACTICS:
        if tactic not in hourly_df.columns:
            hourly_df[tactic] = 0
    
    # Rename to MultivariateForecast expected format: ds, y, + tactic columns
    hourly_df = hourly_df.rename(columns={'timestamp': 'ds', 'total_alerts': 'y'})
    
    logger.info(f"Aggregated hourly series: {len(hourly_df)} time steps")
    logger.info(f"Date range: {hourly_df['ds'].min()} → {hourly_df['ds'].max()}")
    logger.info(f"Total alerts: {hourly_df['y'].sum():,.0f}")
    
    # ─── 2. ACF/PACF DIAGNOSTIC PLOTS ──────────────────────────────────
    logger.info("═══ Running Pre-Training Diagnostics ═══")
    
    # Create indexed series for diagnostics
    ts = hourly_df.set_index('ds')['y']
    
    # Stationarity test (raw)
    raw_stationarity = run_stationarity_test(ts, "Raw Series")
    
    # Stationarity test (first differenced)
    diff_stationarity = run_stationarity_test(ts.diff().dropna(), "1st Differenced")
    
    # Suggest d parameter
    if raw_stationarity['is_stationary']:
        suggested_d = 0
        logger.info("  → Suggested d=0 (series is already stationary)")
    elif diff_stationarity['is_stationary']:
        suggested_d = 1
        logger.info("  → Suggested d=1 (stationary after single differencing)")
    else:
        suggested_d = 2
        logger.info("  → Suggested d=2 (requires double differencing)")
    
    # Generate ACF/PACF plots
    logger.info("Generating ACF/PACF diagnostic plots...")
    generate_acf_pacf_plots(ts, diagnostics_dir, "total_alerts")
    
    # ─── 3. TRAIN USING MultivariateForecast (auto_arima) ──────────────
    logger.info("═══ Training SARIMAX via MultivariateForecast ═══")
    logger.info("auto_arima will search for optimal (p,d,q)(P,D,Q,s=24) parameters...")
    
    forecaster = MultivariateForecast()
    train_stats = forecaster.train(hourly_df)
    
    # ─── 4. LOG RESULTS ────────────────────────────────────────────────
    logger.info("═══ Training Complete ═══")
    logger.info(f"  Samples used: {train_stats['samples']}")
    logger.info(f"  Date range: {train_stats['train_start']} → {train_stats['train_end']}")
    logger.info(f"  Total alerts trained on: {train_stats['total_alerts']:,}")
    logger.info(f"  Avg alerts/hour: {train_stats['avg_per_hour']:.1f}")
    
    best_params = train_stats.get('best_parameters', {})
    if 'order' in best_params:
        p, d, q = best_params['order']
        P, D, Q, s = best_params['seasonal_order']
        logger.info(f"  ┌─ Best SARIMAX Parameters (via auto_arima AIC) ─┐")
        logger.info(f"  │ Non-seasonal: p={p}, d={d}, q={q}               │")
        logger.info(f"  │ Seasonal:     P={P}, D={D}, Q={Q}, s={s}        │")
        logger.info(f"  └───────────────────────────────────────────────────┘")
        logger.info(f"  ADF suggested d={suggested_d}, auto_arima selected d={d}")
        if suggested_d != d:
            logger.warning(f"  ⚠ ADF test suggested d={suggested_d} but auto_arima chose d={d}. "
                          f"Check ACF/PACF plots in {diagnostics_dir} to validate.")
    else:
        logger.info(f"  Fallback model used: {best_params}")
    
    # Log tactic distribution
    logger.info("  MITRE Tactic Distribution:")
    tactic_totals = train_stats.get('tactic_totals', {})
    total = sum(tactic_totals.values()) or 1
    for tactic, count in sorted(tactic_totals.items(), key=lambda x: -x[1]):
        if count > 0:
            logger.info(f"    {tactic:25s}: {count:8,} ({count/total*100:5.1f}%)")
    
    # ─── 5. SAVE MODEL ─────────────────────────────────────────────────
    out_path = models_dir / "attack_forecaster.pkl"
    forecaster.save(str(out_path))
    
    logger.info(f"Model saved → {out_path}")
    logger.info(f"Diagnostics → {diagnostics_dir}")


if __name__ == "__main__":
    train_forecaster()
