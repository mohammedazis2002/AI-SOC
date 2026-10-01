"""
MongoDB Database Initialization Script
Creates collections, indexes, and initial data
"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "backend"))

from config.database import db_manager
from config.settings import settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def create_indexes():
    """Create indexes for all collections"""
    
    logger.info("Creating indexes...")
    
    # alerts_raw collection indexes
    await db_manager.alerts_raw.create_index("alert_id", unique=True)
    await db_manager.alerts_raw.create_index("ingestion_timestamp")
    await db_manager.alerts_raw.create_index("siem_source")
    logger.info("✅ Created indexes for alerts_raw")
    
    # alerts_processed collection indexes
    await db_manager.alerts_processed.create_index("alert_id", unique=True)
    await db_manager.alerts_processed.create_index("severity_id")
    await db_manager.alerts_processed.create_index("siem_source")
    await db_manager.alerts_processed.create_index("ingestion_timestamp")
    await db_manager.alerts_processed.create_index("processing_status")
    
    # Compound index for queries
    await db_manager.alerts_processed.create_index([
        ("siem_source", 1),
        ("severity_id", -1),
        ("ingestion_timestamp", -1)
    ])
    
    # Text index for search
    await db_manager.alerts_processed.create_index([
        ("finding.title", "text"),
        ("finding.desc", "text")
    ])
    
    # TTL index for data retention (90 days)
    await db_manager.alerts_processed.create_index(
        "ingestion_timestamp",
        expireAfterSeconds=settings.alert_retention_days * 24 * 60 * 60
    )
    logger.info("✅ Created indexes for alerts_processed")
    
    # actions_taken collection indexes
    await db_manager.actions_taken.create_index("alert_id")
    await db_manager.actions_taken.create_index("action_timestamp")
    await db_manager.actions_taken.create_index("action_type")
    logger.info("✅ Created indexes for actions_taken")
    
    # model_predictions collection indexes
    await db_manager.model_predictions.create_index("alert_id")
    await db_manager.model_predictions.create_index("model_name")
    await db_manager.model_predictions.create_index("prediction_timestamp")
    logger.info("✅ Created indexes for model_predictions")
    
    # feedback_data collection indexes
    await db_manager.feedback_data.create_index("alert_id")
    await db_manager.feedback_data.create_index("analyst_id")
    await db_manager.feedback_data.create_index("feedback_timestamp")
    logger.info("✅ Created indexes for feedback_data")
    
    # correlation_groups collection indexes
    await db_manager.correlation_groups.create_index("group_id", unique=True)
    await db_manager.correlation_groups.create_index("created_at")
    await db_manager.correlation_groups.create_index("alert_ids")
    logger.info("✅ Created indexes for correlation_groups")
    
    # user_profiles collection indexes (for UBA)
    await db_manager.user_profiles.create_index("user_id", unique=True)
    await db_manager.user_profiles.create_index("last_updated")
    logger.info("✅ Created indexes for user_profiles")
    
    # feedback_collection indexes
    await db_manager.feedback_collection.create_index("incident_id", unique=True)
    await db_manager.feedback_collection.create_index("technique_id")
    await db_manager.feedback_collection.create_index("attack_stage")
    await db_manager.feedback_collection.create_index("decision")
    await db_manager.feedback_collection.create_index("false_positive")
    await db_manager.feedback_collection.create_index("original_plan")
    await db_manager.feedback_collection.create_index("analyst_plan")
    await db_manager.feedback_collection.create_index("removed_actions")
    await db_manager.feedback_collection.create_index("added_actions")
    await db_manager.feedback_collection.create_index("plan_rating")
    await db_manager.feedback_collection.create_index("analyst_metadata.analyst_id")
    await db_manager.feedback_collection.create_index("analyst_metadata.team")
    await db_manager.feedback_collection.create_index("analyst_metadata.confidence")
    await db_manager.feedback_collection.create_index("timestamps.feedback_submitted_at")
    await db_manager.feedback_collection.create_index("timestamps.incident_created_at")
    await db_manager.feedback_collection.create_index("execution_outcome.recurrence_within_7_days")
    logger.info("✅ Created indexes for feedback_collection")
    
    # action_priors_data indexes
    await db_manager.action_priors_data.create_index("technique_id", unique=True)
    await db_manager.action_priors_data.create_index("technique_name")
    await db_manager.action_priors_data.create_index("actions.action")
    await db_manager.action_priors_data.create_index("feedback_sample_size")
    logger.info("✅ Created indexes for action_priors_data")


async def create_collections():
    """Create collections with validators"""
    
    logger.info("Creating collections...")
    
    # Get existing collections
    existing_collections = await db_manager.db.list_collection_names()
    
    collections = [
        "alerts_raw",
        "alerts_processed",
        "actions_taken",
        "model_predictions",
        "feedback_data",
        "correlation_groups",
        "user_profiles",
        "feedback_collection",
        "action_priors_data"
    ]
    
    for collection_name in collections:
        if collection_name not in existing_collections:
            await db_manager.db.create_collection(collection_name)
            logger.info(f"✅ Created collection: {collection_name}")
        else:
            logger.info(f"ℹ️  Collection already exists: {collection_name}")


async def insert_sample_data():
    """Insert sample data for testing (optional)"""
    
    logger.info("Checking for sample data...")
    
    # Check if we already have data
    count = await db_manager.alerts_processed.count_documents({})
    
    if count > 0:
        logger.info(f"ℹ️  Database already has {count} alerts, skipping sample data")
        return
    
    logger.info("Database is empty - you can add sample data later")


async def main():
    """Main initialization function"""
    
    logger.info("=" * 70)
    logger.info("SOAR Platform - Database Initialization")
    logger.info("=" * 70)
    
    try:
        # Connect to MongoDB
        await db_manager.connect()
        
        # Create collections
        await create_collections()
        
        # Create indexes
        await create_indexes()
        
        # Insert sample data (optional)
        await insert_sample_data()
        
        logger.info("=" * 70)
        logger.info("✅ Database initialization completed successfully!")
        logger.info("=" * 70)
        
        # Show database stats
        stats = await db_manager.db.command("dbStats")
        logger.info(f"\nDatabase: {settings.mongodb_database}")
        logger.info(f"Collections: {stats['collections']}")
        logger.info(f"Data Size: {stats['dataSize'] / 1024:.2f} KB")
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        raise
    
    finally:
        await db_manager.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
