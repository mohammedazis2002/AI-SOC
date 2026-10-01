"""
Initialize FP Detector Configuration

Sets up MongoDB collections and default configurations
"""

import logging
from pymongo import MongoClient
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def initialize_fp_detector_config():
    """Initialize FP detector configuration in MongoDB"""
    
    logger.info("Initializing FP Detector configuration...")
    
    db = MongoClient()['soar_db']
    
    # 1. Create collections with indexes
    logger.info("\n1. Creating collections and indexes...")
    
    # noisy_rules collection
    db.noisy_rules.create_index([('rule_id', 1)], unique=True)
    db.noisy_rules.create_index([('fp_rate', -1)])
    logger.info("  ✅ noisy_rules collection")
    
    # fp_feedback collection
    db.fp_feedback.create_index([('alert_id', 1)])
    db.fp_feedback.create_index([('submitted_at', -1)])
    logger.info("  ✅ fp_feedback collection")
    
    # alert_fingerprints collection
    db.alert_fingerprints.create_index([('fingerprint', 1)])
    db.alert_fingerprints.create_index([('last_seen', -1)])
    logger.info("  ✅ alert_fingerprints collection")
    
    # 2. Initialize default scanner IPs
    logger.info("\n2. Initializing scanner IPs whitelist...")
    
    scanner_ips = {
        '_id': 'scanner_ips',
        'name': 'Known Vulnerability Scanner IPs',
        'ips': [
            '10.0.0.50',  # Example Nessus scanner
            '10.0.0.51',  # Example Qualys scanner
        ],
        'last_updated': datetime.now()
    }
    
    db.config.update_one(
        {'_id': 'scanner_ips'},
        {'$set': scanner_ips},
        upsert=True
    )
    logger.info(f"  ✅ Added {len(scanner_ips['ips'])} default scanner IPs")
    
    # 3. Initialize trusted users whitelist
    logger.info("\n3. Initializing trusted users whitelist...")
    
    trusted_users = {
        '_id': 'trusted_users',
        'name': 'Trusted User Whitelist',
        'users': [
            'monitoring_service',
            'backup_account',
            'health_check'
        ],
        'last_updated': datetime.now()
    }
    
    db.config.update_one(
        {'_id': 'trusted_users'},
        {'$set': trusted_users},
        upsert=True
    )
    logger.info(f"  ✅ Added {len(trusted_users['users'])} trusted users")
    
    # 4. Initialize FP detector settings
    logger.info("\n4. Initializing FP detector settings...")
    
    settings = {
        '_id': 'fp_detector_settings',
        'name': 'FP Detector Configuration',
        'auto_close_threshold': 0.90,
        'auto_close_min_confidence': 0.95,
        'suppress_threshold': 0.80,
        'suppress_min_confidence': 0.85,
        'deprioritize_threshold': 0.70,
        'critical_severity_override': True,
        'high_risk_tactic_override': True,
        'high_threat_intel_override': True,
        'never_auto_close_tactics': [
            'initial_access',
            'execution',
            'privilege_escalation',
            'defense_evasion',
            'credential_access',
            'lateral_movement',
            'collection',
            'command_and_control',
            'exfiltration',
            'impact'
        ],
        'last_updated': datetime.now()
    }
    
    db.config.update_one(
        {'_id': 'fp_detector_settings'},
        {'$set': settings},
        upsert=True
    )
    logger.info("  ✅ FP detector settings configured")
    
    # 5. Display configuration summary
    logger.info("\n" + "="*60)
    logger.info("CONFIGURATION SUMMARY")
    logger.info("="*60)
    
    logger.info("\nCollections created:")
    logger.info(f"  - noisy_rules: {db.noisy_rules.count_documents({})}")
    logger.info(f"  - fp_feedback: {db.fp_feedback.count_documents({})}")
    logger.info(f"  - alert_fingerprints: {db.alert_fingerprints.count_documents({})}")
    
    logger.info("\nScanner IPs configured:")
    for ip in scanner_ips['ips']:
        logger.info(f"  - {ip}")
    
    logger.info("\nTrusted users configured:")
    for user in trusted_users['users']:
        logger.info(f"  - {user}")
    
    logger.info("\nThresholds:")
    logger.info(f"  - Auto-close: {settings['auto_close_threshold']} (confidence: {settings['auto_close_min_confidence']})")
    logger.info(f"  - Suppress: {settings['suppress_threshold']} (confidence: {settings['suppress_min_confidence']})")
    logger.info(f"  - Deprioritize: {settings['deprioritize_threshold']}")
    
    logger.info("\n✅ FP Detector configuration complete!")
    logger.info("\nNext steps:")
    logger.info("  1. Add your actual scanner IPs to scanner_ips collection")
    logger.info("  2. Add trusted service accounts to trusted_users collection")
    logger.info("  3. Start collecting analyst feedback (analyst_verdict field)")
    logger.info("  4. Run identify_noisy_rules.py after 100+ labeled alerts")
    logger.info("  5. Train ML model with train_fp_detector.py after 500+ labels")


if __name__ == "__main__":
    initialize_fp_detector_config()
