"""
Helper Script: Identify Noisy Rules

Analyzes historical alerts to identify rules with high FP rates
Updates noisy_rules collection in MongoDB
"""

import logging
from pymongo import MongoClient
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def identify_noisy_rules(min_alerts=50, fp_threshold=0.6):
    """
    Identify and store noisy rules
    
    Args:
        min_alerts: Minimum alert count to consider (default: 50)
        fp_threshold: FP rate threshold (default: 0.6 = 60%)
    """
    
    logger.info("="*60)
    logger.info("NOISY RULES IDENTIFICATION")
    logger.info("="*60)
    logger.info(f"Minimum alerts: {min_alerts}")
    logger.info(f"FP threshold: {fp_threshold*100:.0f}%")
    
    db = MongoClient()['soar_db']
    
    # Check if we have labeled data
    labeled_count = db.alerts.count_documents({'analyst_verdict': {'$exists': True}})
    
    if labeled_count == 0:
        logger.error("❌ No labeled alerts found!")
        logger.error("   Analysts need to label alerts with 'analyst_verdict' field")
        logger.error("   Use the labeling UI or add verdicts manually")
        return
    
    logger.info(f"\nAnalyzing {labeled_count} labeled alerts...")
    
    # Aggregation pipeline
    pipeline = [
        {'$match': {'analyst_verdict': {'$exists': True}}},
        {'$group': {
            '_id': '$unmapped.wazuh_rule_id',
            'rule_name': {'$first': '$finding.title'},
            'total': {'$sum': 1},
            'fp_count': {'$sum': {
                '$cond': [{'$eq': ['$analyst_verdict', 'false_positive']}, 1, 0]
            }},
            'tp_count': {'$sum': {
                '$cond': [{'$eq': ['$analyst_verdict', 'true_positive']}, 1, 0]
            }}
        }},
        {'$project': {
            'rule_id': '$_id',
            'rule_name': 1,
            'total': 1,
            'fp_count': 1,
            'tp_count': 1,
            'fp_rate': {'$divide': ['$fp_count', '$total']}
        }},
        {'$match': {
            'total': {'$gte': min_alerts},
            'fp_rate': {'$gte': fp_threshold}
        }},
        {'$sort': {'fp_rate': -1}}
    ]
    
    noisy_rules = list(db.alerts.aggregate(pipeline))
    
    if not noisy_rules:
        logger.info("\n✅ No noisy rules found (all rules below threshold)")
        return
    
    logger.info(f"\n🔍 Found {len(noisy_rules)} noisy rules:")
    logger.info("\n" + "="*60)
    logger.info(f"{'Rule ID':<15} {'FP Rate':<10} {'Total':<10} {'Rule Name':<25}")
    logger.info("="*60)
    
    for rule in noisy_rules:
        rule_id = rule['rule_id']
        fp_rate = rule['fp_rate']
        total = rule['total']
        rule_name = rule['rule_name'][:40] if rule['rule_name'] else 'Unknown'
        
        logger.info(f"{str(rule_id):<15} {fp_rate:>6.1%}    {total:<10} {rule_name}")
    
    # Update MongoDB collection
    logger.info(f"\n💾 Updating noisy_rules collection...")
    
    db.noisy_rules.delete_many({})  # Clear existing
    
    for rule in noisy_rules:
        rule['last_updated'] = datetime.now()
        db.noisy_rules.insert_one(rule)
    
    logger.info(f"✅ Stored {len(noisy_rules)} noisy rules in database")
    
    # Summary stats
    logger.info("\n" + "="*60)
    logger.info("SUMMARY STATISTICS")
    logger.info("="*60)
    
    avg_fp_rate = sum(r['fp_rate'] for r in noisy_rules) / len(noisy_rules)
    max_fp_rate = max(r['fp_rate'] for r in noisy_rules)
    total_fps = sum(r['fp_count'] for r in noisy_rules)
    
    logger.info(f"Average FP rate: {avg_fp_rate:.1%}")
    logger.info(f"Highest FP rate: {max_fp_rate:.1%}")
    logger.info(f"Total FPs from noisy rules: {total_fps}")
    
    logger.info("\n✅ Done! Noisy rules list updated.")
    logger.info("   These rules will now be flagged in FP detection.")
    
    return noisy_rules


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Identify noisy rules from labeled alerts')
    parser.add_argument('--min-alerts', type=int, default=50,
                        help='Minimum alert count (default: 50)')
    parser.add_argument('--fp-threshold', type=float, default=0.6,
                        help='FP rate threshold 0.0-1.0 (default: 0.6)')
    
    args = parser.parse_args()
    
    identify_noisy_rules(
        min_alerts=args.min_alerts,
        fp_threshold=args.fp_threshold
    )
