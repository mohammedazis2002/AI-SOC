"""
Training Script for Anomaly Detector (Model 1)
Run this script once you have 30 days of alerts in MongoDB
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from services.ml.anomaly_detector import AnomalyDetector
from config.database import get_database
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_alerts_from_mongodb(days=30, limit=50000):
    """
    Load historical alerts from MongoDB
    
    Args:
        days: Number of days of history to load
        limit: Maximum number of alerts to load
        
    Returns:
        List of alert dictionaries
    """
    db = get_database()
    
    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    logger.info(f"Loading alerts from {start_date} to {end_date}")
    
    # Query MongoDB
    cursor = db.alerts_processed.find({
        "timestamp": {
            "$gte": start_date,
            "$lte": end_date
        }
    }).limit(limit)
    
    alerts = list(cursor)
    logger.info(f"Loaded {len(alerts)} alerts from MongoDB")
    
    return alerts


def main():
    """Main training function"""
    logger.info("="*60)
    logger.info("ANOMALY DETECTOR TRAINING")
    logger.info("Model 1: Isolation Forest")
    logger.info("="*60)
    
    # Step 1: Load data
    logger.info("\n📥 Step 1: Loading training data...")
    alerts = load_alerts_from_mongodb(days=30, limit=50000)
    
    if len(alerts) == 0:
        logger.error("❌ No alerts found in MongoDB!")
        logger.error("Please ensure you have at least 30 days of alerts before training.")
        return
    
    if len(alerts) < 1000:
        logger.warning(f"⚠️  Only {len(alerts)} alerts found.")
        logger.warning("Recommended: 10,000+ alerts for good performance.")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return
    
    # Step 2: Initialize detector
    logger.info("\n🧠 Step 2: Initializing Anomaly Detector...")
    detector = AnomalyDetector()
    logger.info(f"   Features: {len(detector.feature_names)}")
    logger.info(f"   Algorithm: Isolation Forest")
    logger.info(f"   Contamination: {detector.model.contamination}")
    
    # Step 3: Train
    logger.info("\n🎯 Step 3: Training model...")
    stats = detector.train(alerts)
    
    # Step 4: Display results
    logger.info("\n"   ✅ TRAINING COMPLETE!")
    logger.info("\n📊 Training Statistics:")
    logger.info(f"   Alerts processed: {stats['num_alerts_trained']:,}")
    logger.info(f"   Features extracted: {stats['num_features']}")
    logger.info(f"   Estimated anomalies: {stats['estimated_anomalies']:,}")
    logger.info(f"   Anomaly rate: {stats['anomaly_rate']:.2%}")
    
    # Step 5: Test on sample
    logger.info("\n🧪 Step 4: Testing on sample alert...")
    test_alert = alerts[0]
    result = detector.predict(test_alert)
    
    logger.info(f"   Sample alert: {test_alert.get('alert_id', 'N/A')}")
    logger.info(f"   Anomaly score: {result['anomaly_score']:.3f}")
    logger.info(f"   Is anomaly: {result['is_anomaly']}")
    logger.info(f"   Confidence: {result['confidence']:.3f}")
    
    # Step 6: Save model
    logger.info("\n💾 Step 5: Saving model...")
    detector.save("models/anomaly_detector.pkl")
    logger.info("   Model saved successfully!")
    
    logger.info("\n" + "="*60)
    logger.info("✅ TRAINING COMPLETED SUCCESSFULLY")
    logger.info("="*60)
    logger.info("\nNext steps:")
    logger.info("1. Deploy the model service: python services/ml/anomaly_detector_service.py")
    logger.info("2. Integrate into alert pipeline")
    logger.info("3. Monitor anomaly scores in dashboard")


if __name__ == "__main__":
    main()
