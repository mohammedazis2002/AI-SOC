"""
Training Script for Root Cause Analyzer - Model 3
Semi-supervised approach with auto-labeling
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from backend.services.ml.root_cause_analyzer import RootCauseAnalyzer
from backend.services.ml.root_cause_feature_extractor import RootCauseFeatureExtractor
from config.database import get_database
import numpy as np
import logging
from typing import List, Dict
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_training_data(db, min_samples: int = 100) -> tuple:
    """
    Load training data from MongoDB
   
    Uses semi-supervised approach:
    1. Load analyst-labeled data (gold standard)
    2. Load auto-labeled data (silver standard)
    3. Combine for training
    
    Args:
        db: MongoDB database
        min_samples: Minimum samples needed
        
    Returns:
        (features, labels, metadata)
    """
    logger.info("Loading training data...")
    
    # Priority 1: Analyst-labeled data
    analyst_labeled = list(db.root_cause_training.find({
        'labeling_method': 'analyst_reviewed'
    }))
    
    logger.info(f"Found {len(analyst_labeled)} analyst-labeled samples")
    
    # Priority 2: Auto-suggested & confirmed
    auto_confirmed = list(db.root_cause_training.find({
        'labeling_method': 'auto_confirmed'
    }))
    
    logger.info(f"Found {len(auto_confirmed)} auto-confirmed samples")
    
    # Combine
    all_samples = analyst_labeled + auto_confirmed
    
    if len(all_samples) < min_samples:
        logger.warning(f"Only {len(all_samples)} samples, need {min_samples}+")
        logger.warning("Consider using auto-labeling to generate more training data")
    
    # Extract features and labels
    X = []
    y = []
    metadata = []
    
    for sample in all_samples:
        # Features
        features = sample.get('features')
        if isinstance(features, dict):
            # Convert dict to array
            feature_array = list(features.values())
            X.append(feature_array)
        else:
            X.append(features)
        
        # Labels (binary matrix)
        labels = sample.get('labels', {})
        label_vector = [
            labels.get(category, 0)
            for category in RootCauseAnalyzer.CATEGORIES
        ]
        y.append(label_vector)
        
        # Metadata
        metadata.append({
            'alert_id': sample.get('alert_id'),
            'labeled_by': sample.get('labeled_by'),
            'confidence': sample.get('confidence', 1.0)
        })
    
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    
    logger.info(f"Loaded {len(X)} samples with {X.shape[1]} features")
    logger.info(f"Label matrix shape: {y.shape}")
    
    return X, y, metadata


def auto_label_historical_data(db, limit: int = 500):
    """
    Auto-label historical alerts for semi-supervised training
    
    Generates training candidates that analysts can quickly review
    
    Args:
        db: MongoDB database
        limit: Max alerts to auto-label
    """
    logger.info(f"Auto-labeling up to {limit} historical alerts...")
    
    # Get recent resolved alerts that aren't labeled yet
    cutoff_date = datetime.utcnow() - timedelta(days=90)
    
    unlabeled_alerts = db.alerts_processed.find({
        'time': {'$gte': cutoff_date},
        'severity_id': {'$gte': 3},  # Medium+ severity
        'has_root_cause_label': {'$ne': True}
    }).limit(limit)
    
    analyzer = RootCauseAnalyzer()
    feature_extractor = RootCauseFeatureExtractor(db)
    
    labeled_count = 0
    
    for alert in unlabeled_alerts:
        try:
            # Auto-suggest labels
            suggestions = analyzer.auto_suggest_labels(alert)
            
            # Only keep if at least one suggestion is confident
            confident_suggestions = {
                cat: sug for cat, sug in suggestions.items()
                if sug['confidence'] >= 0.75
            }
            
            if not confident_suggestions:
                continue
            
            # Extract features
            features = feature_extractor.extract(alert, context={})
            
            # Create training sample
            training_sample = {
                'alert_id': str(alert.get('_id')),
                'alert': alert,
                'features': features.tolist(),
                'labels': {
                    cat: sug['suggested']
                    for cat, sug in suggestions.items()
                },
                'label_confidences': {
                    cat: sug['confidence']
                    for cat, sug in confident_suggestions.items()
                },
                'labeling_method': 'auto_suggested',
                'needs_review': True,
                'created_at': datetime.utcnow()
            }
            
            # Insert
            db.root_cause_training.insert_one(training_sample)
            labeled_count += 1
            
        except Exception as e:
            logger.warning(f"Failed to auto-label alert {alert.get('_id')}: {e}")
            continue
    
    logger.info(f"✅ Auto-labeled {labeled_count} alerts for analyst review")


def train_model(min_samples: int = 100, auto_label_first: bool = True):
    """
    Train Root Cause Analyzer
    
    Args:
        min_samples: Minimum training samples
        auto_label_first: If True, auto-label historical data before training
    """
    db = get_database()
    
    # Step 1: Auto-label if needed
    if auto_label_first:
        existing_count = db.root_cause_training.count_documents({})
        if existing_count < min_samples:
            logger.info(f"Only {existing_count} samples, running auto-labeling...")
            auto_label_historical_data(db, limit=500)
    
    # Step 2: Load training data
    X, y, metadata = load_training_data(db, min_samples=min_samples)
    
    if len(X) < min_samples:
        logger.error(f"Insufficient training data: {len(X)} < {min_samples}")
        logger.error("Please label more alerts or lower min_samples threshold")
        return
    
    # Step 3: Split train/test
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    logger.info(f"Train set: {len(X_train)} samples")
    logger.info(f"Test set: {len(X_test)} samples")
    
    # Step 4: Train
    analyzer = RootCauseAnalyzer()
    train_stats = analyzer.train(X_train, y_train, feature_names=RootCauseFeatureExtractor.FEATURE_NAMES)
    
    # Step 5: Evaluate
    logger.info("\nEvaluating on test set...")
    y_pred_proba = analyzer.predict(X_test, return_proba=True)
    y_pred = (y_pred_proba >= 0.5).astype(int)
    
    # Metrics
    from sklearn.metrics import hamming_loss, accuracy_score, precision_recall_fscore_support
    
    hamming = hamming_loss(y_test, y_pred)
    
    # Per-category metrics
    logger.info("\nPer-category performance:")
    for i, category in enumerate(RootCauseAnalyzer.CATEGORIES):
        precision, recall, f1, support = precision_recall_fscore_support(
            y_test[:, i], y_pred[:, i], average='binary', zero_division=0
        )
        logger.info(f"  {category:25s}: P={precision:.2f} R={recall:.2f} F1={f1:.2f} (n={int(support)})")
    
    logger.info(f"\nOverall Hamming Loss: {hamming:.4f}")
    
    # Step 6: Save model
    analyzer.save("models/root_cause_analyzer.pkl")
    logger.info("✅ Model saved to models/root_cause_analyzer.pkl")
    
    # Step 7: Test on sample
    logger.info("\nTesting on sample alert...")
    sample_features = X_test[0]
    analysis = analyzer.analyze_alert(sample_features, alert_context={
        'mitre_tactic': 'credential_access'
    })
    
    logger.info(f"Root causes found: {analysis['num_root_causes']}")
    for cause in analysis['root_causes']:
        logger.info(f"  - {cause['cause']}: {cause['confidence']:.2f} [{cause.get('priority', 'N/A')}]")
    
    logger.info("\nRemediation:")
    for step in analysis['remediation']:
        logger.info(f"  {step}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Train Root Cause Analyzer")
    parser.add_argument('--min-samples', type=int, default=100, help='Minimum training samples')
    parser.add_argument('--auto-label', action='store_true', help='Auto-label historical data first')
    parser.add_argument('--no-auto-label', dest='auto_label', action='store_false')
    parser.set_defaults(auto_label=True)
    
    args = parser.parse_args()
    
    train_model(min_samples=args.min_samples, auto_label_first=args.auto_label)
