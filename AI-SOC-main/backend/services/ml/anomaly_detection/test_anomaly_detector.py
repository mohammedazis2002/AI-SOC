"""
Test script for Anomaly Detector
Tests model with sample alerts before training on real data
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from backend.services.ml.anomaly_detector import AnomalyDetector
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_sample_alerts():
    """Create sample alerts for testing"""
    return [
        {
            "alert_id": "TEST-NORMAL-001",
            "timestamp": datetime(2026, 1, 20, 14, 30, 0).isoformat(),
            "rule_level": 3,
            "severity_id": 2,
            "rule_description": "User logged in successfully",
            "rule_groups": ["authentication"],
            "mitre_ids": [],
            "src_endpoint": {"ip": "10.0.0.50", "port": 54321},
            "dst_endpoint": {"ip": "10.0.0.5", "port": 22},
            "actor": {"name": "john_doe"},
            "agent_id": "001",
            "full_log": "Accepted password for john_doe from 10.0.0.50"
        },
        {
            "alert_id": "TEST-ANOMALY-001",
            "timestamp": datetime(2026, 1, 20, 2, 15, 0).isoformat(),  # 2 AM
            "rule_level": 10,
            "severity_id": 5,
            "rule_description": "Multiple failed SSH login attempts",
            "rule_groups": ["authentication", "attack"],
            "mitre_ids": ["T1110", "T1078"],
            "src_endpoint": {"ip": "203.0.113.45", "port": 12345},  # External IP
            "dst_endpoint": {"ip": "10.0.0.5", "port": 22},
            "actor": {"name": "root"},
            "agent_id": "001",
            "full_log": "Failed password for root from 203.0.113.45 port 12345 ssh2"
        },
        {
            "alert_id": "TEST-NORMAL-002",
            "timestamp": datetime(2026, 1, 20, 10, 45, 0).isoformat(),  # Business hours
            "rule_level": 2,
            "severity_id": 1,
            "rule_description": "System update check",
            "rule_groups": ["system"],
            "mitre_ids": [],
            "src_endpoint": {"ip": "10.0.0.100", "port": 443},
            "dst_endpoint": {"ip": "10.0.0.1", "port": 80},
            "actor": {"name": "system"},
            "agent_id": "002",
            "full_log": "apt update completed successfully"
        }
    ]


def test_feature_extraction():
    """Test that feature extraction works"""
    logger.info("="*60)
    logger.info("TEST 1: Feature Extraction")
    logger.info("="*60)
    
    detector = AnomalyDetector()
    alerts = create_sample_alerts()
    
    logger.info(f"\nExtracting features from {len(alerts)} sample alerts...")
    features = detector.extract_features(alerts)
    
    logger.info(f"✅ Features extracted successfully")
    logger.info(f"   Shape: {features.shape}")
    logger.info(f"   Expected: ({len(alerts)}, 48)")
    
    assert features.shape == (len(alerts), 48), f"Expected shape (3, 48), got {features.shape}"
    
    logger.info("\n✅ TEST PASSED: Feature extraction working correctly")
    return True


def test_training():
    """Test model training with sample data"""
    logger.info("\n" + "="*60)
    logger.info("TEST 2: Model Training")
    logger.info("="*60)
    
    detector = AnomalyDetector()
    
    # Create more sample alerts for training
    alerts = create_sample_alerts() * 100  # 300 alerts
    logger.info(f"\nTraining on {len(alerts)} sample alerts...")
    
    stats = detector.train(alerts)
    
    logger.info(f"✅ Training completed")
    logger.info(f"   Alerts trained: {stats['num_alerts_trained']}")
    logger.info(f"   Features: {stats['num_features']}")
    logger.info(f"   Estimated anomalies: {stats['estimated_anomalies']}")
    logger.info(f"   Anomaly rate: {stats['anomaly_rate']:.2%}")
    
    assert detector.trained, "Model should be marked as trained"
    
    logger.info("\n✅ TEST PASSED: Model training successful")
    return detector


def test_prediction(detector):
    """Test prediction on new alerts"""
    logger.info("\n" + "="*60)
    logger.info("TEST 3: Prediction")
    logger.info("="*60)
    
    alerts = create_sample_alerts()
    
    logger.info("\nTesting predictions on sample alerts:")
    
    for alert in alerts:
        result = detector.predict(alert)
        
        logger.info(f"\n  Alert: {alert['alert_id']}")
        logger.info(f"    Type: {alert['rule_description']}")
        logger.info(f"    Time: {alert['timestamp']}")
        logger.info(f"    Anomaly Score: {result['anomaly_score']:.3f}")
        logger.info(f"    Is Anomaly: {result['is_anomaly']}")
        logger.info(f"    Confidence: {result['confidence']:.3f}")
        
        # Verify response structure
        assert 'anomaly_score' in result
        assert 'is_anomaly' in result
        assert 'confidence' in result
        assert 0 <= result['anomaly_score'] <= 1
    
    logger.info("\n✅ TEST PASSED: Predictions working correctly")
    return True


def test_save_load(detector):
    """Test model save/load"""
    logger.info("\n" + "="*60)
    logger.info("TEST 4: Save/Load Model")
    logger.info("="*60)
    
    # Save
    logger.info("\nSaving model...")
    detector.save("models/test_anomaly_detector.pkl")
    logger.info("✅ Model saved")
    
    # Load
    logger.info("\nLoading model...")
    new_detector = AnomalyDetector()
    new_detector.load("models/test_anomaly_detector.pkl")
    logger.info("✅ Model loaded")
    
    # Verify loaded model works
    test_alert = create_sample_alerts()[0]
    result = new_detector.predict(test_alert)
    logger.info(f"✅ Loaded model prediction successful: {result['anomaly_score']:.3f}")
    
    logger.info("\n✅ TEST PASSED: Save/load working correctly")
    return True


def main():
    """Run all tests"""
    logger.info("\n" + "🧪 "*30)
    logger.info("ANOMALY DETECTOR - TEST SUITE")
    logger.info("🧪 "*30 + "\n")
    
    try:
        # Test 1: Feature extraction
        test_feature_extraction()
        
        # Test 2: Training
        detector = test_training()
        
        # Test 3: Prediction
        test_prediction(detector)
        
        # Test 4: Save/Load
        test_save_load(detector)
        
        # All tests passed
        logger.info("\n" + "="*60)
        logger.info("✅ ALL TESTS PASSED!")
        logger.info("="*60)
        logger.info("\nThe Anomaly Detector is ready to use.")
        logger.info("Next step: Train on real data with train_anomaly_detector.py")
        
    except Exception as e:
        logger.error(f"\n❌ TEST FAILED: {e}")
        raise


if __name__ == "__main__":
    main()
