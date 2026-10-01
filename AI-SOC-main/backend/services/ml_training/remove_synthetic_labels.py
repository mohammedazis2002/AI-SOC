"""
Remove synthetic labels from MongoDB alerts.
We'll use real analyst labels via the labeling UI instead.
"""

import logging
from pymongo import MongoClient

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def remove_synthetic_labels():
    """Remove all synthetic training labels from alerts"""
    
    logger.info("="*60)
    logger.info("REMOVING SYNTHETIC LABELS")
    logger.info("="*60)
    
    # Connect to MongoDB
    client = MongoClient("mongodb://localhost:27017/")
    db = client["soar"]
    coll = db["alerts_processed"]
    
    total = coll.count_documents({})
    logger.info(f"\nTotal alerts in collection: {total:,}")
    
    # Count labeled alerts
    labeled = coll.count_documents({'is_labeled': True})
    logger.info(f"Alerts with synthetic labels: {labeled:,}")
    
    if labeled == 0:
        logger.info("✅ No synthetic labels found. Collection is clean.")
        return
    
    # Remove synthetic label fields
    logger.info("\nRemoving label fields...")
    
    result = coll.update_many(
        {},
        {'$unset': {
            'analyst_verdict': '',
            'outcome': '',
            'investigation_time_minutes': '',
            'labeled_at': '',
            'is_labeled': ''
        }}
    )
    
    logger.info(f"✅ Removed labels from {result.modified_count:,} alerts")
    
    # Verify
    remaining = coll.count_documents({'is_labeled': True})
    logger.info(f"\nVerification: {remaining} alerts still have 'is_labeled' field")
    
    logger.info("\n" + "="*60)
    logger.info("✅ CLEANUP COMPLETE")
    logger.info("="*60)
    logger.info("\nAlerts are ready for real analyst labeling via UI")


if __name__ == "__main__":
    remove_synthetic_labels()
