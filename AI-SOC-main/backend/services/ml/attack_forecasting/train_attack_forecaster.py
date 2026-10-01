"""
Training Script for Attack Forecaster (Model 5 - Auto-ARIMA/SARIMAX)
Trains multivariate forecaster with automatic parameter selection
"""

import sys
from pathlib import Path
# Add backend to path when running from project root
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from backend.services.ml.attack_forecasting.attack_forecaster import MultivariateForecast
from pymongo import MongoClient
from datetime import datetime, timedelta
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# All 14 MITRE ATT&CK tactics
TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access',
    'execution', 'persistence', 'privilege_escalation',
    'defense_evasion', 'credential_access', 'discovery',
    'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact', 'unknown'
]


def load_hourly_data_from_mongodb(months=3):
    """
    Load hourly data with MITRE tactic breakdown from MongoDB
    
    Args:
        months: Number of months of history to load
        
    Returns:
        DataFrame with hourly counts and tactic breakdown
    """
    client = MongoClient("mongodb://localhost:27017/")
    db = client["soar"]
    
    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30 * months)
    
    logger.info(f"Loading hourly data from {start_date} to {end_date}")
    
    # Get all alerts in range
    alerts = list(db.alerts_processed.find({
        "timestamp": {"$gte": start_date, "$lte": end_date}
    }))
    
    if len(alerts) == 0:
        logger.error("No alerts found in MongoDB!")
        return None
    
    logger.info(f"Loaded {len(alerts)} alerts")
    
    # Convert to DataFrame
    df = pd.DataFrame(alerts)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Extract MITRE tactic (first tactic if multiple)
    def get_tactic(row):
        try:
            tactics = row.get('rule', {}).get('mitre', {}).get('tactic', [])
            if isinstance(tactics, list) and len(tactics) > 0:
                return tactics[0].lower().replace(' ', '_')
            return 'unknown'
        except:
            return 'unknown'
    
    df['tactic'] = df.apply(get_tactic, axis=1)
    
    # Aggregate by hour
    df['hour'] = df['timestamp'].dt.floor('H')
    
    # Create hourly counts with tactic breakdown
    hourly_data = []
    
    for hour in pd.date_range(start_date, end_date, freq='H'):
        hour_alerts = df[df['hour'] == hour]
        total_count = len(hour_alerts)
        
        row = {
            'ds': hour,
            'y': total_count
        }
        
        # Add tactic counts
        for tactic in TACTICS:
            row[tactic] = len(hour_alerts[hour_alerts['tactic'] == tactic])
        
        hourly_data.append(row)
    
    result = pd.DataFrame(hourly_data)
    logger.info(f"Created {len(result)} hourly data points")
    
    return result


def main():
    """Main training function"""
    logger.info("="*60)
    logger.info("ATTACK FORECASTER TRAINING")
    logger.info("Model 5: Auto-ARIMA/SARIMAX with Auto Parameter Selection")
    logger.info("="*60)
    
    # Step 1: Load data
    logger.info("\n📥 Step 1: Loading hourly alert data with MITRE breakdown...")
    hourly_data = load_hourly_data_from_mongodb(months=3)
    
    if hourly_data is None or len(hourly_data) == 0:
        logger.error("❌ No data found in MongoDB!")
        logger.error("Please run: python backend/services/ml_training/load_data_to_mongodb.py")
        return
    
    if len(hourly_data) < 168:  # 1 week
        logger.warning(f"⚠️  Only {len(hourly_data)} hours of data ({len(hourly_data)/24:.1f} days).")
        logger.warning("Recommended: 1+ week (168 hours) for Auto-ARIMA.")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return
    
    # Step 2: Initialize forecaster
    logger.info("\n🔮 Step 2: Initializing Multivariate Forecaster...")
    forecaster = MultivariateForecast()
    logger.info("   Algorithm: Auto-ARIMA/SARIMAX")
    logger.info("   Auto parameter selection: YES")
    logger.info("   Seasonality: 24-hour cycle")
    logger.info("   Confidence: 80%")
    
    # Step 3: Train
    logger.info("\n🎯 Step 3: Training model (this may take a few minutes)...")
    logger.info("   Auto-ARIMA will search for optimal (p,d,q) parameters...")
    stats = forecaster.train(hourly_data)
    
    # Step 4: Display results
    logger.info("\n✅ TRAINING COMPLETE!")
    logger.info("\n📊 Training Statistics:")
    logger.info(f"   Data points: {stats['samples']:,} hours")
    logger.info(f"   Date range: {stats['train_start']} to {stats['train_end']}")
    logger.info(f"   Total alerts: {stats['total_alerts']:,}")
    logger.info(f"   Avg/hour: {stats['avg_per_hour']:.1f}")
    logger.info(f"\n🤖 Model: {stats['model']}")
    if 'best_parameters' in stats and stats['best_parameters']:
        params = stats['best_parameters']
        if 'order' in params:
            logger.info(f"   Best parameters: ARIMA{params['order']} x {params.get('seasonal_order', 'N/A')}")
    
    # Display tactic distribution
    logger.info("\n📊 MITRE Tactic Distribution:")
    tactic_totals = stats.get('tactic_totals', {})
    sorted_tactics = sorted(tactic_totals.items(), key=lambda x: x[1], reverse=True)
    for tactic, count in sorted_tactics[:10]:  # Top 10
        if count > 0:
            logger.info(f"   {tactic:25s}: {count:,} alerts")
    
    # Step 5: Test forecast
    logger.info("\n🧪 Step 4: Testing forecast (next 24 hours)...")
    forecast = forecaster.forecast(hours_ahead=24)
    
    logger.info(f"   Forecast start: {forecast['forecast_start']}")
    logger.info(f"   Forecast end: {forecast['forecast_end']}")
    logger.info(f"   Average predicted: {forecast['statistics']['avg_predicted']:.1f} alerts/hour")
    logger.info(f"   Peak predicted: {forecast['statistics']['max_predicted']} alerts/hour")
    logger.info(f"   High-risk hours: {forecast['statistics']['high_risk_count']}")
    
    if forecast['high_risk_windows']:
        logger.info("\n⚠️  High-Risk Windows Detected:")
        for window in forecast['high_risk_windows'][:3]:  # Show first 3
            logger.info(f"   • {window['timestamp']}: {window['predicted_alerts']} alerts ({window['risk_level']})")
    
    # Step 6: Get next risk window
    logger.info("\n🚨 Step 5: Next high-risk window...")
    next_risk = forecaster.get_next_high_risk_window()
    
    if next_risk['has_risk']:
        logger.info(f"   ⚠️  ALERT: High-risk window in {next_risk['hours_until']:.1f} hours")
        logger.info(f"   Time: {next_risk['timestamp']}")
        logger.info(f"   Risk: {next_risk['risk_level'].upper()}")
        logger.info(f"   Expected: {next_risk['predicted_alerts']} alerts")
        logger.info(f"   Action: {next_risk['recommendation']}")
    else:
        logger.info(f"   ✅ {next_risk['message']}")
    
    # Step 7: Save model
    logger.info("\n💾 Step 6: Saving model...")
    Path("models").mkdir(exist_ok=True)
    forecaster.save("models/attack_forecaster.pkl")
    logger.info("   Model saved to models/attack_forecaster.pkl")
    
    logger.info("\n" + "="*60)
    logger.info("✅ TRAINING COMPLETED SUCCESSFULLY")
    logger.info("="*60)
    logger.info("\nNext steps:")
    logger.info("1. Deploy the forecaster service: python backend/services/ml/attack_forecasting/attack_forecaster_service.py")
    logger.info("2. Test the service: curl http://localhost:5003/forecast?hours=24")
    logger.info("3. Schedule retraining every week")


if __name__ == "__main__":
    main()
