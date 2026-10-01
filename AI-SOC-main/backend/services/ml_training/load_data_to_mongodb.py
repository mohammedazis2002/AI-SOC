"""
Load synthetic Wazuh alerts into MongoDB
This allows existing training scripts to work without modification
"""

import json
import sys
from pathlib import Path
from pymongo import MongoClient, ASCENDING
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_alerts_to_mongodb(
    json_path: str,
    mongo_uri: str = "mongodb://localhost:27017/",
    database: str = "soar",
    collection: str = "alerts_processed"
):
    """
    Load synthetic alerts from JSON into MongoDB.
    
    Args:
        json_path: Path to synthetic_wazuh_alerts.json
        mongo_uri: MongoDB connection string
        database: Database name
        collection: Collection name
    """
    
    logger.info("="*60)
    logger.info("LOADING SYNTHETIC ALERTS INTO MONGODB")
    logger.info("="*60)
    
    # Step 1: Load JSON data
    logger.info(f"\n📥 Step 1: Loading JSON from {json_path}")
    
    with open(json_path, 'r') as f:
        alerts = json.load(f)
    
    logger.info(f"   Loaded {len(alerts):,} alerts")
    
    # Step 2: Connect to MongoDB
    logger.info(f"\n🔌 Step 2: Connecting to MongoDB")
    logger.info(f"   URI: {mongo_uri}")
    logger.info(f"   Database: {database}")
    logger.info(f"   Collection: {collection}")
    
    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        # Test connection
        client.server_info()
        logger.info("   ✅ Connected successfully")
    except Exception as e:
        logger.error(f"   ❌ Failed to connect to MongoDB: {e}")
        logger.error("\nPlease ensure MongoDB is running:")
        logger.error("   Windows: net start MongoDB")
        logger.error("   Linux/Mac: sudo systemctl start mongod")
        return False
    
    db = client[database]
    coll = db[collection]
    
    # Step 3: Check if data already exists
    existing_count = coll.count_documents({})
    
    if existing_count > 0:
        logger.warning(f"\n⚠️  Collection already contains {existing_count:,} documents")
        response = input("   Clear and reload? (y/n): ")
        if response.lower() == 'y':
            logger.info("   Clearing existing data...")
            coll.delete_many({})
            logger.info("   ✅ Cleared")
        else:
            logger.info("   Appending to existing data...")
    
    # Step 4: Transform data (add timestamp field if needed)
    logger.info(f"\n🔄 Step 3: Preparing data for MongoDB")
    
    for alert in alerts:
        # Ensure timestamp field exists (some training scripts use 'time', some use 'timestamp')
        if 'timestamp' in alert and 'time' not in alert:
            # Parse ISO timestamp string to datetime
            ts_str = alert['timestamp']
            if isinstance(ts_str, str):
                alert['time'] = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            else:
                alert['time'] = ts_str  # Already datetime
        
        # Add processing metadata
        alert['loaded_at'] = datetime.utcnow()
        alert['source'] = 'synthetic_training_data'
    
    # Step 5: Insert into MongoDB
    logger.info(f"\n💾 Step 4: Inserting {len(alerts):,} alerts into MongoDB")
    logger.info("   This may take a minute...")
    
    try:
        # Batch insert for efficiency
        result = coll.insert_many(alerts, ordered=False)
        logger.info(f"   ✅ Inserted {len(result.inserted_ids):,} documents")
    except Exception as e:
        logger.error(f"   ❌ Insert failed: {e}")
        return False
    
    # Step 6: Create indexes for performance
    logger.info(f"\n🔍 Step 5: Creating indexes")
    
    indexes = [
        ('time', ASCENDING),
        ('timestamp', ASCENDING),
        ('rule.level', ASCENDING),
        ('agent.name', ASCENDING)
    ]
    
    for field, order in indexes:
        try:
            coll.create_index([(field, order)])
            logger.info(f"   ✅ Created index on '{field}'")
        except Exception as e:
            logger.warning(f"   ⚠️  Failed to create index on '{field}': {e}")
    
    # Step 7: Verify
    logger.info(f"\n✅ Step 6: Verification")
    
    total_docs = coll.count_documents({})
    logger.info(f"   Total documents: {total_docs:,}")
    
    # Sample document
    sample = coll.find_one()
    if sample:
        logger.info(f"   Sample ID: {sample.get('id', 'N/A')}")
        logger.info(f"   Sample timestamp: {sample.get('time', sample.get('timestamp', 'N/A'))}")
        logger.info(f"   Sample rule level: {sample.get('rule', {}).get('level', 'N/A')}")
    
    # Date range
    pipeline = [
        {"$group": {
            "_id": None,
            "min_time": {"$min": "$time"},
            "max_time": {"$max": "$time"}
        }}
    ]
    
    date_range = list(coll.aggregate(pipeline))
    if date_range:
        logger.info(f"   Date range: {date_range[0]['min_time']} to {date_range[0]['max_time']}")
    
    logger.info("\n" + "="*60)
    logger.info("✅ DATA LOADED SUCCESSFULLY")
    logger.info("="*60)
    logger.info("\nReady to train ML models!")
    logger.info("Run individual training scripts now.")
    
    return True


if __name__ == "__main__":
    # Configuration
    JSON_PATH = "Attack_Data_Syn/synthetic_wazuh_alerts.json"
    MONGO_URI = "mongodb://localhost:27017/"
    DATABASE = "soar"
    COLLECTION = "alerts_processed"
    
    # Load data
    success = load_alerts_to_mongodb(JSON_PATH, MONGO_URI, DATABASE, COLLECTION)
    
    if success:
        print("\n🎉 Ready to train models!")
        print("\nNext steps:")
        print("1. cd backend/services/ml/false_positive_detection")
        print("2. python train_fp_detector.py")
        print("... (repeat for each model)")
    else:
        print("\n❌ Data loading failed. Please fix errors and try again.")
        sys.exit(1)
