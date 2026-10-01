"""
Populate MongoDB with sample historical alerts

This creates realistic alert history for testing context building
and root cause analysis with non-zero risk scores.
"""

import logging
from datetime import datetime, timedelta
from pymongo import MongoClient
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_sample_alerts():
    """Create sample historical alerts for testing"""
    
    client = MongoClient()
    db = client['soar_db']
    
    logger.info("Creating sample historical alerts...")
    
    now = datetime.now()
    alerts = []
    
    # User: jdoe - Normal user with some failed logins
    for i in range(15):
        days_ago = random.randint(1, 30)
        alert_time = now - timedelta(days=days_ago)
        
        alerts.append({
            "alert_id": f"hist_alert_jdoe_{i}",
            "time": int(alert_time.timestamp() * 1000),
            "severity_id": random.choice([1, 2, 3]),  # Low to High
            "class_uid": 3002,  # Authentication
            "status_id": 2 if i < 5 else 1,  # 5 failures, rest success
            "finding": {
                "title": "Login attempt" if i >= 5 else "Failed login",
                "types": [],
                "desc": "User authentication event"
            },
            "actor": {
                "user": {
                    "name": "jdoe",
                    "type_id": 1,
                    "groups": ["developers"]
                }
            },
            "src_endpoint": {
                "ip": f"192.168.1.{100 + i}"
            },
            "dst_endpoint": {
                "hostname": "web-server-01"
            }
        })
    
    # User: admin - Privileged user with high severity alerts
    for i in range(8):
        days_ago = random.randint(1, 30)
        alert_time = now - timedelta(days=days_ago)
        
        alerts.append({
            "alert_id": f"hist_alert_admin_{i}",
            "time": int(alert_time.timestamp() * 1000),
            "severity_id": random.choice([3, 4]),  # High to Critical
            "class_uid": 3002,
            "status_id": 1,
            "finding": {
                "title": "Privileged account activity",
                "types": ["T1078"],
                "desc": "Admin account login from unusual location"
            },
            "actor": {
                "user": {
                    "name": "admin",
                    "type_id": 2,  # Admin
                    "groups": ["Domain Admins"]
                }
            },
            "src_endpoint": {
                "ip": f"10.0.0.{10 + i}"
            },
            "dst_endpoint": {
                "hostname": "dc01.corp.local"
            },
            "enrichments": {
                "mitre": {
                    "techniques": ["T1078"],
                    "tactics": ["initial_access"],
                    "dominant_tactic": "initial_access"
                }
            }
        })
    
    # Add some policy violations
    for i in range(3):
        days_ago = random.randint(1, 30)
        alert_time = now - timedelta(days=days_ago)
        
        alerts.append({
            "alert_id": f"hist_compliance_{i}",
            "time": int(alert_time.timestamp() * 1000),
            "severity_id": 2,
            "class_uid": 6003,  # Compliance Finding
            "finding": {
                "title": "Policy violation detected",
                "types": [],
                "desc": "User accessed restricted resource"
            },
            "actor": {
                "user": {
                    "name": "jdoe",
                    "type_id": 1
                }
            }
        })
    
    # Insert all alerts
    if alerts:
        result = db.alerts.insert_many(alerts)
        logger.info(f"✅ Inserted {len(result.inserted_ids)} historical alerts")
    
    # Create an open incident for testing
    incident = {
        "incident_id": "INC-001",
        "status": "investigating",
        "severity": "high",
        "entities": {
            "user": "jdoe",
            "assets": ["web-server-01"]
        },
        "created_at": now - timedelta(days=2),
        "alerts": alerts[:3]  # Link first 3 alerts
    }
    
    db.incidents.insert_one(incident)
    logger.info("✅ Created 1 open incident")
    
    # Show summary
    logger.info("\n" + "="*60)
    logger.info("DATABASE SUMMARY")
    logger.info("="*60)
    
    total_alerts = db.alerts.count_documents({})
    jdoe_alerts = db.alerts.count_documents({"actor.user.name": "jdoe"})
    admin_alerts = db.alerts.count_documents({"actor.user.name": "admin"})
    failed_logins = db.alerts.count_documents({
        "actor.user.name": "jdoe",
        "class_uid": 3002,
        "status_id": 2
    })
    high_severity = db.alerts.count_documents({
        "actor.user.name": "jdoe",
        "severity_id": {"$gte": 3}
    })
    
    logger.info(f"Total Alerts: {total_alerts}")
    logger.info(f"  - jdoe: {jdoe_alerts}")
    logger.info(f"  - admin: {admin_alerts}")
    logger.info(f"\njdoe Statistics:")
    logger.info(f"  - Failed logins: {failed_logins}")
    logger.info(f"  - High severity alerts: {high_severity}")
    logger.info(f"  - Policy violations: 3")
    logger.info(f"  - Open incidents: 1")
    
    # Calculate expected risk score
    expected_risk = (
        min(high_severity * 4, 40) +
        min(failed_logins * 3, 30) +
        min(3 * 4, 20) +
        min(1 * 5, 10)
    )
    logger.info(f"\nExpected Risk Score for jdoe: ~{expected_risk}/100")
    
    logger.info("\n✅ Database populated! Run tests again to see non-zero values.")


if __name__ == "__main__":
    create_sample_alerts()
