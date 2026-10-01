"""
Train False Positive Detector

Trains Random Forest model on labeled alerts
Requires 500+ labeled alerts to run
"""

import logging
import numpy as np
from pymongo import MongoClient
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
from datetime import datetime
from pathlib import Path

from backend.services.ml.fp_feature_extractor import FPFeatureExtractor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def train_fp_detector():
    """Train FP detector model"""
    
    logger.info("Starting FP detector training...")
    
    # Connect to MongoDB
    db = MongoClient()['soar_db']
    feature_extractor = FPFeatureExtractor(db)
    
    # Load labeled data
    logger.info("Loading labeled alerts...")
    labeled_alerts = list(db.alerts.find({
        'analyst_verdict': {'$exists': True}
    }))
    
    if len(labeled_alerts) < 100:
        logger.error(f"Insufficient training data: {len(labeled_alerts)} alerts")
        logger.error("Need at least 100 labeled alerts (500+ recommended)")
        return
    
    logger.info(f"Found {len(labeled_alerts)} labeled alerts")
    
    # Extract features and labels
    X = []
    y = []
    
    for alert in labeled_alerts:
        try:
            features = feature_extractor.extract(alert)
            X.append(features)
            
            # Label: 1 = FP, 0 = TP
            label = 1 if alert['analyst_verdict'] == 'false_positive' else 0
            y.append(label)
        except Exception as e:
            logger.warning(f"Failed to extract features from alert {alert.get('alert_id')}: {e}")
    
    X = np.array(X)
    y = np.array(y)
    
    logger.info(f"Feature matrix shape: {X.shape}")
    logger.info(f"Label distribution: FP={sum(y)}, TP={len(y)-sum(y)}")
    
    # Check for class imbalance
    fp_rate = sum(y) / len(y)
    logger.info(f"FP rate in training data: {fp_rate:.2%}")
    
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info(f"Training set: {len(X_train)} samples")
    logger.info(f"Test set: {len(X_test)} samples")
    
    # Train Random Forest
    logger.info("Training Random Forest...")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',  # Handle imbalanced data
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    logger.info("\n" + "="*60)
    logger.info("TRAINING RESULTS")
    logger.info("="*60)
    
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"\nAccuracy: {accuracy:.2%}")
    
    # Classification report
    logger.info("\nClassification Report:")
    logger.info(classification_report(
        y_test, y_pred,
        target_names=['True Positive', 'False Positive']
    ))
    
    # Confusion matrix
    logger.info("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"              Predicted TP  Predicted FP")
    logger.info(f"Actual TP     {cm[0][0]:>12}  {cm[0][1]:>12}")
    logger.info(f"Actual FP     {cm[1][0]:>12}  {cm[1][1]:>12}")
    
    # Feature importance
    logger.info("\nTop 10 Most Important Features:")
    feature_names = [
        'severity', 'class_uid', 'alert_freq', 'fp_keywords', 'threat_intel',
        'confidence', 'noisy_rule', 'mitre_tactic',
        'known_good_user', 'service_account', 'scanner', 'dev_env', 
        'internal_src', 'privilege_level',
        'business_hours', 'weekend', 'time_entropy', 'repeated_pattern', 
        'time_since_similar',
        'similar_fp_count', 'similar_tp_count', 'fp_rate_rule', 
        'dismissed_count', 'avg_investigation_time', 'escalation_rate'
    ]
    
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for i in range(min(10, len(feature_names))):
        idx = indices[i]
        logger.info(f"  {i+1}. {feature_names[idx]:25s}: {importances[idx]:.4f}")
    
    # Save model
    model_dir = Path('models')
    model_dir.mkdir(exist_ok=True)
    
    model_path = model_dir / 'fp_detector.pkl'
    
    model_data = {
        'model': model,
        'feature_names': feature_names,
        'metadata': {
            'trained_at': datetime.now().isoformat(),
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'accuracy': float(accuracy),
            'fp_rate_training': float(fp_rate)
        }
    }
    
    joblib.dump(model_data, model_path)
    logger.info(f"\n✅ Model saved to {model_path}")
    
    # Performance recommendation
    logger.info("\n" + "="*60)
    logger.info("DEPLOYMENT RECOMMENDATION")
    logger.info("="*60)
    
    if accuracy >= 0.90:
        logger.info("✅ EXCELLENT - Deploy to production")
    elif accuracy >= 0.85:
        logger.info("✅ GOOD - Deploy with monitoring")
    elif accuracy >= 0.80:
        logger.info("⚠️  FAIR - Consider collecting more data")
    else:
        logger.info("❌ POOR - Collect more training data before deployment")
    
    return model, accuracy


if __name__ == "__main__":
    train_fp_detector()
