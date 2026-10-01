"""
Initialize MongoDB Collections for Context Building

This script creates the 'users' and 'assets' collections with proper indexes
and optionally populates them with sample/imported data.

Run this once to set up the database schema.
"""

import logging
from pymongo import MongoClient, ASCENDING
from datetime import datetime
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def initialize_collections(mongo_uri: str = "mongodb://localhost:27017/", db_name: str = "soar_db"):
    """
    Initialize users and assets collections with indexes.
    """
    client = MongoClient(mongo_uri)
    db = client[db_name]
    
    logger.info(f"Initializing collections in database: {db_name}")
    
    # ========== USERS COLLECTION ==========
    
    logger.info("Setting up 'users' collection...")
    
    # Drop existing if you want a fresh start (optional)
    # db.users.drop()
    
    # Create indexes
    db.users.create_index([("username", ASCENDING)], unique=True)
    db.users.create_index([("uid", ASCENDING)], sparse=True)
    db.users.create_index([("department", ASCENDING)])
    db.users.create_index([("is_admin", ASCENDING)])
    
    logger.info("✅ 'users' collection indexes created")
    
    # Optional: Insert sample users for testing
    sample_users = [
        {
            "username": "admin",
            "uid": "0",
            "type": "admin",
            "is_admin": True,
            "department": "IT",
            "groups": ["Domain Admins", "Administrators"],
            "created_at": datetime(2020, 1, 1),
            "email": "admin@company.com",
            "manager": None,
            "last_seen": datetime.now()
        },
        {
            "username": "jdoe",
            "uid": "1001",
            "type": "user",
            "is_admin": False,
            "department": "engineering",
            "groups": ["developers", "vpn-users"],
            "created_at": datetime(2025, 9, 15),
            "email": "jdoe@company.com",
            "manager": "mjones",
            "last_seen": datetime.now()
        },
        {
            "username": "serviceaccount",
            "uid": "2001",
            "type": "service",
            "is_admin": False,
            "department": "automation",
            "groups": ["service-accounts"],
            "created_at": datetime(2024, 5, 1),
            "email": None,
            "manager": None,
            "last_seen": datetime.now()
        }
    ]
    
    for user in sample_users:
        try:
            db.users.update_one(
                {"username": user["username"]},
                {"$setOnInsert": user},
                upsert=True
            )
            logger.info(f"  ✅ Sample user '{user['username']}' added")
        except Exception as e:
            logger.warning(f"  ⚠️  User '{user['username']}' already exists or error: {e}")
    
    # ========== ASSETS COLLECTION ==========
    
    logger.info("\nSetting up 'assets' collection...")
    
    # Drop existing if you want a fresh start (optional)
    # db.assets.drop()
    
    # Create indexes
    db.assets.create_index([("hostname", ASCENDING)], unique=True)
    db.assets.create_index([("ip", ASCENDING)], sparse=True)
    db.assets.create_index([("environment", ASCENDING)])
    db.assets.create_index([("criticality", ASCENDING)])
    db.assets.create_index([("owner", ASCENDING)])
    
    logger.info("✅ 'assets' collection indexes created")
    
    # Optional: Insert sample assets for testing
    sample_assets = [
        {
            "hostname": "dc01.corp.local",
            "ip": "10.0.0.10",
            "os": {
                "type": "Windows Server 2019",
                "version": "10.0.17763"
            },
            "criticality": 5,  # Mission critical (Domain Controller)
            "environment": "production",
            "owner": "infrastructure-team",
            "department": "IT",
            "last_patch_date": datetime(2026, 1, 15),
            "pending_cves": [],
            "created_at": datetime(2020, 1, 1),
            "last_seen": datetime.now()
        },
        {
            "hostname": "web-server-01",
            "ip": "10.0.1.50",
            "os": {
                "type": "Ubuntu 22.04",
                "version": "22.04.3"
            },
            "criticality": 4,  # Critical (Public-facing)
            "environment": "production",
            "owner": "web-team",
            "department": "engineering",
            "last_patch_date": datetime(2026, 1, 20),
            "pending_cves": [
                {
                    "cve_id": "CVE-2024-12345",
                    "severity": "medium",
                    "detected_date": datetime(2026, 1, 22)
                }
            ],
            "created_at": datetime(2024, 6, 1),
            "last_seen": datetime.now()
        },
        {
            "hostname": "dev-workstation-05",
            "ip": "192.168.10.105",
            "os": {
                "type": "Windows 11",
                "version": "10.0.22631"
            },
            "criticality": 2,  # Low (Dev machine)
            "environment": "development",
            "owner": "jdoe",
            "department": "engineering",
            "last_patch_date": datetime(2026, 1, 10),
            "pending_cves": [],
            "created_at": datetime(2025, 11, 1),
            "last_seen": datetime.now()
        }
    ]
    
    for asset in sample_assets:
        try:
            db.assets.update_one(
                {"hostname": asset["hostname"]},
                {"$setOnInsert": asset},
                upsert=True
            )
            logger.info(f"  ✅ Sample asset '{asset['hostname']}' added")
        except Exception as e:
            logger.warning(f"  ⚠️  Asset '{asset['hostname']}' already exists or error: {e}")
    
    # ========== SUMMARY ==========
    
    logger.info("\n" + "="*60)
    logger.info("INITIALIZATION COMPLETE")
    logger.info("="*60)
    
    user_count = db.users.count_documents({})
    asset_count = db.assets.count_documents({})
    alert_count = db.alerts.count_documents({})
    
    logger.info(f"📊 Database Statistics:")
    logger.info(f"  - Users:  {user_count}")
    logger.info(f"  - Assets: {asset_count}")
    logger.info(f"  - Alerts: {alert_count}")
    
    logger.info("\n✅ Collections ready for context building!")
    logger.info("   Run root_cause_service.py to start using ContextBuilder")
    
    return {
        "users": user_count,
        "assets": asset_count,
        "alerts": alert_count
    }


def import_from_csv(csv_path: str, collection_type: str):
    """
    Import users or assets from CSV file.
    
    Args:
        csv_path: Path to CSV file
        collection_type: 'users' or 'assets'
    """
    import csv
    
    client = MongoClient()
    db = client['soar_db']
    
    logger.info(f"Importing {collection_type} from {csv_path}...")
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        count = 0
        
        for row in reader:
            if collection_type == 'users':
                doc = {
                    "username": row['username'],
                    "type": row.get('type', 'user'),
                    "is_admin": row.get('is_admin', 'false').lower() == 'true',
                    "department": row.get('department', 'unknown'),
                    "created_at": datetime.fromisoformat(row['created_at']) if 'created_at' in row else datetime.now()
                }
            elif collection_type == 'assets':
                doc = {
                    "hostname": row['hostname'],
                    "criticality": int(row.get('criticality', 3)),
                    "environment": row.get('environment', 'unknown'),
                    "owner": row.get('owner', 'unknown'),
                    "created_at": datetime.now()
                }
            else:
                logger.error(f"Unknown collection type: {collection_type}")
                return
            
            db[collection_type].update_one(
                {"username" if collection_type == 'users' else "hostname": doc["username" if collection_type == 'users' else "hostname"]},
                {"$setOnInsert": doc},
                upsert=True
            )
            count += 1
        
        logger.info(f"✅ Imported {count} {collection_type}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Initialize MongoDB collections for context building")
    parser.add_argument('--mongo-uri', default='mongodb://localhost:27017/', help='MongoDB connection URI')
    parser.add_argument('--db-name', default='soar_db', help='Database name')
    parser.add_argument('--import-users', help='CSV file to import users from')
    parser.add_argument('--import-assets', help='CSV file to import assets from')
    parser.add_argument('--no-samples', action='store_true', help='Skip creating sample data')
    
    args = parser.parse_args()
    
    # Initialize collections
    if not args.no_samples:
        stats = initialize_collections(args.mongo_uri, args.db_name)
    else:
        logger.info("Skipping sample data creation (--no-samples flag)")
        client = MongoClient(args.mongo_uri)
        db = client[args.db_name]
        db.users.create_index([("username", ASCENDING)], unique=True)
        db.assets.create_index([("hostname", ASCENDING)], unique=True)
        logger.info("✅ Indexes created")
    
    # Import from CSV if specified
    if args.import_users:
        import_from_csv(args.import_users, 'users')
    
    if args.import_assets:
        import_from_csv(args.import_assets, 'assets')
    
    logger.info("\n🎉 Setup complete!")
