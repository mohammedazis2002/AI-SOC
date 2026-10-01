import logging
import yaml
import pandas as pd
import numpy as np
import pickle
import sys
from pathlib import Path
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from statsmodels.graphics.tsaplots import plot_acf, plot_pacf

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def validate_forecaster(config_path="backend/scripts/train_models/configs/scaling_config.yaml"):
    root_dir = Path(__file__).resolve().parents[4]
    
    with open(root_dir / config_path, "r") as f:
        config = yaml.safe_load(f)
        
    wazuh_interim = root_dir / config["paths"]["wazuh_interim"]
    models_dir = root_dir / config["paths"]["models_out"]
    diagnostics_dir = models_dir / "diagnostics"
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    
    parquet_files = list(wazuh_interim.glob("*.parquet"))
    if not parquet_files:
        logger.error(f"Raw parquet files missing in {wazuh_interim}.")
        return
        
    logger.info("Loading wazuh raw parquet files for validation...")
    df = pd.concat([pd.read_parquet(f) for f in parquet_files], ignore_index=True)
    
    # 1. Depend on feature engineering fix: Use the updated timestamps & columns
    df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
    df = df.set_index('timestamp')
    
    # Aggregate to hourly counts
    hourly_df = df.resample('1H').size().reset_index(name='y')
    hourly_df = hourly_df.rename(columns={'timestamp': 'ds'})
    
    logger.info(f"Aggregated Validation Series: {len(hourly_df)} hours")
    
    if len(hourly_df) < 10:
        logger.warning("Insufficient data for validation plots.")
        return
        
    ts = hourly_df.set_index('ds')['y']
    
    # Generate ACF and PACF plots
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    nlags = min(48, len(ts) // 2 - 1)
    
    fig, axes = plt.subplots(2, 1, figsize=(12, 10))
    fig.suptitle('Forecaster Validation: ACF and PACF Diagnostics', fontsize=14, fontweight='bold')
    
    # Raw series ACF
    plot_acf(ts.dropna(), ax=axes[0], lags=nlags, title='Autocorrelation Function (ACF)')
    # Raw series PACF
    plot_pacf(ts.dropna(), ax=axes[1], lags=nlags, title='Partial Autocorrelation Function (PACF)', method='ywm')
    
    for ax in axes:
        ax.grid(True, alpha=0.3)
        
    plt.tight_layout()
    out_path = diagnostics_dir / f"validation_acf_pacf_{timestamp_str}.png"
    fig.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    logger.info(f"✅ Validation ACF/PACF plot saved to: {out_path}")
    
    # Load Model to check parameters
    model_path = models_dir / "attack_forecaster.pkl"
    if model_path.exists():
        with open(model_path, 'rb') as f:
            save_data = pickle.load(f)
            best_params = save_data.get('best_params', {})
            logger.info(f"✅ Loaded Forecaster Model. Optimal Hyperparameters used: {best_params}")
            
        sys.path.append(str(root_dir))
        from backend.services.ml.attack_forecasting.attack_forecaster import MultivariateForecast
        forecaster = MultivariateForecast()
        forecaster.load(str(model_path))
        
        logger.info("✅ Validated model loads successfully with Auto-ARIMA architecture.")
    else:
        logger.warning(f"Model file not found at {model_path}. Train the model first.")

if __name__ == "__main__":
    validate_forecaster()
