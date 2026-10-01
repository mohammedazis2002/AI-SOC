"""
Attack Forecasting Training - Direct Approach
Simplest possible version to avoid pandas issues
"""

import numpy as np
from pymongo import MongoClient
from datetime import timedelta
from pathlib import Path
import logging
import pickle
from pmdarima import auto_arima
from sklearn.metrics import mean_squared_error, mean_absolute_error
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def main():
    logger.info("="*60)
    logger.info("ATTACK FORECASTER TRAINING - SIMPLIFIED")
    logger.info("="*60)
    
    # Load and aggregate data
    logger.info("\n📥 Loading alerts...")
    client = MongoClient("mongodb://localhost:27017/")
    alerts = list(client.soar.alerts_processed.find({}))
    logger.info(f"   Loaded {len(alerts):,} alerts")
    
    # Create hourly counts manually
    from collections import defaultdict
    from datetime import datetime
    
    hourly = defaultdict(int)
    for alert in alerts:
        ts = alert['timestamp']
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        hour = ts.replace(minute=0, second=0, microsecond=0)
        hourly[hour] += 1
    
    # Sort by time
    sorted_hours = sorted(hourly.keys())
    counts = [hourly[h] for h in sorted_hours]
    
    logger.info(f"   Created {len(counts)} hourly data points")
    logger.info(f"   Range: {sorted_hours[0]} to {sorted_hours[-1]}")
    logger.info(f"   Total: {sum(counts):,} alerts")
    logger.info(f"   Avg: {np.mean(counts):.1f}/hour")
    
    # Train/test split
    split = int(len(counts) * 0.8)
    train_counts = counts[:split]
    test_counts = counts[split:]
    
    logger.info(f"\n✂️  Split: {len(train_counts)} train, {len(test_counts)} test")
    
    # Train
    logger.info(f"\n🎯 Training Auto-ARIMA...")
    
    model = auto_arima(
        train_counts,
        seasonal=True,
        m=24,
        start_p=0, max_p=2,  # Reduced search space for speed
        start_q=0, max_q=2,
        start_P=0, max_P=1,
        start_Q=0, max_Q=1,
        max_d=2,
        max_D=1,
        trace=False,
        error_action='ignore',
        suppress_warnings=True,
        stepwise=True
    )
    
    logger.info(f"✅ Model: ARIMA{model.order} x {model.seasonal_order}")
    logger.info(f"   AIC: {model.aic():.2f}")
    
    # Predict on test set
    logger.info(f"\n📊 Evaluating...")
    
    try:
        # Get predictions
        preds = model.predict(n_periods=len(test_counts))
        preds = np.array(preds)
        preds = np.maximum(0, preds)  # Non-negative
        
        actual = np.array(test_counts)
        
        # Metrics
        rmse = np.sqrt(mean_squared_error(actual, preds))
        mae = mean_absolute_error(actual, preds)
        mape = np.mean(np.abs((actual - preds) / np.maximum(actual, 1))) * 100
        r2 = 1 - (np.sum((actual - preds)**2) / np.sum((actual - np.mean(actual))**2))
        acc = np.sum(np.abs(actual - preds) <= (actual * 0.2 + 1)) / len(actual) * 100
        
        logger.info(f"\n{'='*60}")
        logger.info("EVALUATION METRICS")
        logger.info(f"{'='*60}")
        logger.info(f"Test Size: {len(test_counts)} hours ({len(test_counts)/24:.1f} days)")
        logger.info(f"\n📈 Errors:")
        logger.info(f"   RMSE: {rmse:.2f} alerts/hour")
        logger.info(f"   MAE:  {mae:.2f} alerts/hour")
        logger.info(f"   MAPE: {mape:.2f}%")
        logger.info(f"\n🎯 Performance:")
        logger.info(f"   R² Score:        {r2:.4f}")
        logger.info(f"   Accuracy (±20%): {acc:.1f}%")
        logger.info(f"\n📊 Comparison:")
        logger.info(f"   Actual   - Mean: {np.mean(actual):.1f}, Max: {np.max(actual):.0f}")
        logger.info(f"   Predicted - Mean: {np.mean(preds):.1f}, Max: {np.max(preds):.0f}")
        
        # Sample predictions
        logger.info(f"\n🔍 First 12 Test Hours:")
        logger.info(f"   {'Hr':<3} {'Actual':<7} {'Pred':<7} {'Error':<7}")
        logger.info(f"   {'-'*30}")
        for i in range(min(12, len(actual))):
            logger.info(f"   {i:<3} {actual[i]:<7.0f} {preds[i]:<7.1f} {actual[i]-preds[i]:+7.1f}")
        
        logger.info(f"\n{'='*60}")
        
        # Forecast future
        logger.info(f"\n🔮 Forecasting next 24 hours...")
        future = model.predict(n_periods=24)
        future = np.maximum(0, future)
        
        high_count = np.sum(future >= 15)
        if high_count > 0:
            logger.info(f"   ⚠️  {high_count} high-risk hours predicted")
            logger.info(f"   Peak: {np.max(future):.1f} alerts/hour")
        else:
            logger.info(f"   ✅ No high-risk windows")
        logger.info(f"   Average: {np.mean(future):.1f} alerts/hour")
        
        # Save
        logger.info(f"\n💾 Saving model...")
        Path("models").mkdir(exist_ok=True)
        
        save_data = {
            'model_fit': model,
            'trained': True,
            'train_start': sorted_hours[0],
            'train_end': sorted_hours[split-1],
            'best_params': {
                'order': model.order,
                'seasonal_order': model.seasonal_order
            },
            'test_metrics': {
                'rmse': float(rmse),
                'mae': float(mae),
                'mape': float(mape),
                'r2': float(r2),
                'accuracy_20pct': float(acc)
            }
        }
        
        with open("models/attack_forecaster.pkl", 'wb') as f:
            pickle.dump(save_data, f)
        
        logger.info("   ✅ Saved to models/attack_forecaster.pkl")
        
        logger.info("\n" + "="*60)
        logger.info("✅ TRAINING COMPLETE!")
        logger.info("="*60)
        logger.info(f"\n🎯 Summary:")
        logger.info(f"   Model: ARIMA{model.order} x {model.seasonal_order}")
        logger.info(f"   RMSE: {rmse:.2f} | R²: {r2:.4f} | Accuracy: {acc:.1f}%")
        logger.info(f"\n✅ Ready for deployment!")
        
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        logger.info("\nSaving model anyway (training was successful)...")
        
        Path("models").mkdir(exist_ok=True)
        save_data = {
            'model_fit': model,
            'trained': True,
            'train_start': sorted_hours[0],
            'train_end': sorted_hours[split-1],
            'best_params': {
                'order': model.order,
                'seasonal_order': model.seasonal_order
            }
        }
        with open("models/attack_forecaster.pkl", 'wb') as f:
            pickle.dump(save_data, f)
        logger.info("✅ Model saved (without evaluation metrics)")


if __name__ == "__main__":
    main()
