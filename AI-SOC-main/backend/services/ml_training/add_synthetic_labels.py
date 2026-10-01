"""
Add synthetic labels to alerts in MongoDB for ML training.

The existing training scripts expect labeled data with analyst verdicts,
but our synthetic alerts don't have these. We'll add realistic labels based on
rule characteristics.
"""

import logging
from pymongo import MongoClient
from random import random

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def add_synthetic_labels():
    """Add analyst_verdict and other ML training labels to alerts"""
    
    logger.info("="*60)
    logger.info("ADDING SYNTHETIC LABELS FOR ML TRAINING")
    logger.info("="*60)
    
    # Connect to MongoDB
    client = MongoClient("mongodb://localhost:27017/")
    db = client["soar"]
    coll = db["alerts_processed"]
    
    total = coll.count_documents({})
    logger.info(f"\nProcessing {total:,} alerts...")
    
    updated = 0
    
    for alert in coll.find({}):
        rule = alert.get('rule', {})
        level = rule.get('level', 5)
        
        # Generate synthetic labels based on rule characteristics
        
        # 1. Analyst Verdict (for FP detection training)
        # Low severity = higher chance of FP
        if level <= 3:
            fp_probability = 0.4  # 40% FP for low severity
        elif level <= 7:
            fp_probability = 0.15  # 15% FP for medium
        elif level <= 10:
            fp_probability = 0.08  # 8% FP for high
        else:
            fp_probability = 0.02  # 2% FP for critical
        
        is_fp = random() < fp_probability
        analyst_verdict = 'false_positive' if is_fp else 'true_positive'
        
        # 2. Attack outcome (for forecasting/root cause)
        outcomes = ['blocked', 'detected', 'contained', 'escalated']
        if level >= 10:
            outcome = 'escalated' if random() < 0.7 else 'contained'
        elif level >= 8:
            outcome = 'contained' if random() < 0.6 else 'detected'
        else:
            outcome = 'detected' if random() < 0.5 else 'blocked'
        
        # 3. Investigation time (minutes)
        if is_fp:
            investigation_time = int(random() * 10 + 2)  # 2-12 min for FP
        elif level >= 10:
            investigation_time = int(random() * 120 + 30)  # 30-150 min for critical
        else:
            investigation_time = int(random() * 60 + 10)  # 10-70 min for others
        
        # Update alert with labels
        coll.update_one(
            {'_id': alert['_id']},
            {'$set': {
                'analyst_verdict': analyst_verdict,
                'outcome': outcome,
                'investigation_time_minutes': investigation_time,
                'labeled_at': 'synthetic',
                'is_labeled': True
            }}
        )
        
        updated += 1
        
        if updated % 5000 == 0:
            logger.info(f"   Processed {updated:,}/{total:,} alerts...")
    
    logger.info(f"\n✅ Updated {updated:,} alerts with synthetic labels")
    
    # Verify distribution
    fp_count = coll.count_documents({'analyst_verdict': 'false_positive'})
    tp_count = coll.count_documents({'analyst_verdict': 'true_positive'})
    
    logger.info(f"\nLabel Distribution:")
    logger.info(f"   False Positives: {fp_count:,} ({fp_count/total*100:.1f}%)")
    logger.info(f"   True Positives: {tp_count:,} ({tp_count/total*100:.1f}%)")
    
    logger.info("\n" + "="*60)
    logger.info("✅ LABELS ADDED SUCCESSFULLY")
    logger.info("="*60)
    logger.info("\nReady to train ML models with labeled data!")


if __name__ == "__main__":
    add_synthetic_labels()
