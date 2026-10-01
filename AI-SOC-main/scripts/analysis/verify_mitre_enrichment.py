"""
Verify MITRE Enrichment in MongoDB
Simple script to check if alerts have MITRE enrichment data
"""

from pymongo import MongoClient
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_database():
    """Connect to MongoDB"""
    try:
        client = MongoClient("mongodb://localhost:27017/")
        db = client['soar_db']
        logger.info("✅ Connected to MongoDB")
        return db
    except Exception as e:
        logger.error(f"❌ Failed to connect to MongoDB: {e}")
        return None


def verify_mitre_enrichment():
    """Check if alerts in MongoDB have MITRE enrichment"""
    logger.info("="*60)
    logger.info("MITRE ENRICHMENT VERIFICATION")
    logger.info("="*60)
    
    db = get_database()
    if db is None:
        return
    
    # Count alerts
    total = db.alerts_processed.count_documents({})
    with_mitre = db.alerts_processed.count_documents({
        "mitre_enrichment.has_mitre_data": True
    })
    
    logger.info(f"\n📊 MongoDB Statistics:")
    logger.info(f"  Total alerts: {total}")
    logger.info(f"  With MITRE enrichment: {with_mitre}")
    
    if total == 0:
        logger.warning("\n⚠️  No alerts in MongoDB yet.")
        logger.info("Process some alerts first, then run this verification.")
        return
    
    coverage = (with_mitre / total * 100) if total > 0 else 0
    logger.info(f"  Coverage: {coverage:.1f}%")
    
    if with_mitre > 0:
        logger.info(f"\n✅ MITRE enrichment is working!")
        
        # Show sample
        logger.info(f"\n📋 Sample Enriched Alert:")
        sample = db.alerts_processed.find_one({
            "mitre_enrichment.has_mitre_data": True
        })
        
        if sample:
            logger.info(f"\n  Alert ID: {sample.get('alert_id')}")
            logger.info(f"  Finding: {sample.get('finding', {}).get('title', 'N/A')}")
            
            enrichment = sample.get('mitre_enrichment', {})
            logger.info(f"\n  MITRE Enrichment:")
            logger.info(f"    Dominant Tactic: {enrichment.get('dominant_tactic')}")
            logger.info(f"    Tactics: {[t['name'] for t in enrichment.get('tactics', [])]}")
            logger.info(f"    Techniques: {[t['id'] + ' (' + t['name'] + ')' for t in enrichment.get('techniques', [])]}")
        
        # Tactic distribution
        logger.info(f"\n📈 Tactic Distribution:")
        pipeline = [
            {"$match": {"mitre_enrichment.has_mitre_data": True}},
            {"$group": {
                "_id": "$mitre_enrichment.dominant_tactic",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        
        for tactic in db.alerts_processed.aggregate(pipeline):
            logger.info(f"  {tactic['_id']:25} : {tactic['count']:4} alerts")
        
        logger.info("\n" + "="*60)
        logger.info("✅ VERIFICATION PASSED")
        logger.info("MITRE enrichment is being saved correctly!")
        logger.info("="*60)
    
    else:
        logger.warning(f"\n⚠️  No alerts with MITRE data found.")
        logger.info("This means:")
        logger.info("  1. All alerts lack MITRE technique IDs in finding.types, OR")
        logger.info("  2. Alerts were ingested before MITRE enrichment was added")
        logger.info("\nTo fix:")
        logger.info("  - Process new alerts with Wazuh (they have MITRE data)")
        logger.info("  - Check that finding.types field has technique IDs like ['T1110']")


if __name__ == "__main__":
    verify_mitre_enrichment()
