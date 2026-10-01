"""
Data Extraction for ML Models
Converts OCSF ULF alerts into training data for Prophet and LSTM models
"""

from config.database import get_database
from datetime import datetime, timedelta
from typing import List, Dict
import pandas as pd
import logging

logger = logging.getLogger(__name__)


def extract_hourly_attack_counts_by_tactic(months: int = 6) -> pd.DataFrame:
    """
    Extract hourly alert counts grouped by MITRE tactic for Prophet training
    
    Args:
        months: Number of months of history to load (default: 6)
        
    Returns:
        DataFrame with columns:
            - ds (timestamp): Hourly timestamp
            - y (int): Total alert count
            - reconnaissance (int): Count
            - resource_development (int): Count
            - initial_access (int): Count
            - execution (int): Count
            - persistence (int): Count
            - privilege_escalation (int): Count
            - defense_evasion (int): Count
            - credential_access (int): Count
            - discovery (int): Count
            - lateral_movement (int): Count
            - collection (int): Count
            - command_and_control (int): Count
            - exfiltration (int): Count
            - impact (int): Count
            - unknown (int): Count (alerts without MITRE data)
    """
    db = get_database()
    
    # All MITRE tactics (normalized names)
    TACTICS = [
        'reconnaissance', 'resource_development', 'initial_access',
        'execution', 'persistence', 'privilege_escalation',
        'defense_evasion', 'credential_access', 'discovery',
        'lateral_movement', 'collection', 'command_and_control',
        'exfiltration', 'impact', 'unknown'
    ]
    
    # Date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30 * months)
    
    logger.info(f"Loading alerts from {start_date} to {end_date}")
    
    # Query all alerts with MITRE enrichment
    query = {
        "time": {"$gte": start_date, "$lte": end_date}
    }
    
    try:
        alerts = list(db.alerts_processed.find(query))
        logger.info(f"Loaded {len(alerts)} alerts")
    except Exception as e:
        logger.error(f"Failed to load alerts: {e}")
        return pd.DataFrame()
    
    # Process into hourly bins
    hourly_bins = {}
    
    for alert in alerts:
        # Get timestamp
        alert_time = alert.get('time') or alert.get('timestamp')
        
        if alert_time is None:
            continue
        
        # Convert to datetime if needed
        if isinstance(alert_time, int):
            alert_time = datetime.fromtimestamp(alert_time / 1000)
        elif isinstance(alert_time, str):
            alert_time = datetime.fromisoformat(alert_time.replace('Z', '+00:00'))
        
        # Round to hour
        hour_key = alert_time.replace(minute=0, second=0, microsecond=0)
        
        # Initialize hour if not exists
        if hour_key not in hourly_bins:
            hourly_bins[hour_key] = {tactic: 0 for tactic in TACTICS}
            hourly_bins[hour_key]['total'] = 0
        
        # Get MITRE tactic from enrichment
        mitre_enrich = alert.get('mitre_enrichment', {})
        
        if mitre_enrich.get('has_mitre_data'):
            # Use dominant tactic
            tactic = mitre_enrich.get('dominant_tactic', 'unknown')
            # Normalize tactic name (replace hyphens with underscores)
            tactic = tactic.replace('-', '_')
        else:
            tactic = 'unknown'
        
        # Increment counts
        if tactic in hourly_bins[hour_key]:
            hourly_bins[hour_key][tactic] += 1
        else:
            hourly_bins[hour_key]['unknown'] += 1
        
        hourly_bins[hour_key]['total'] += 1
    
    # Convert to DataFrame for Prophet
    data = []
    for hour, counts in sorted(hourly_bins.items()):
        row = {'ds': hour, 'y': counts['total']}
        # Add all tactic counts
        for tactic in TACTICS:
            row[tactic] = counts[tactic]
        data.append(row)
    
    df = pd.DataFrame(data)
    
    logger.info(f"Created DataFrame with {len(df)} hourly data points")
    logger.info(f"Date range: {df['ds'].min()} to {df['ds'].max()}")
    logger.info(f"Total alerts: {df['y'].sum()}")
    
    # Show tactic distribution
    logger.info("\nTactic Distribution:")
    for tactic in TACTICS:
        count = df[tactic].sum()
        pct = (count / df['y'].sum() * 100) if df['y'].sum() > 0 else 0
        logger.info(f"  {tactic}: {int(count)} ({pct:.1f}%)")
    
    return df


def extract_attack_sequences(months: int = 6, min_chain_length: int = 5) -> List[List[Dict]]:
    """
    Extract attack sequences for LSTM training
    
    Groups related alerts into attack chains for sequence prediction
    
    Args:
        months: Number of months of history
        min_chain_length: Minimum alerts in a chain to include
        
    Returns:
        List of attack chains, where each chain is a list of alerts in sequence
        [
            [  # Chain 1
                {stage: "reconnaissance", technique: "T1595", time: 0, ...},
                {stage: "initial_access", technique: "T1190", time: 300, ...},
                ...
            ],
            [  # Chain 2
                ...
            ]
        ]
    """
    db = get_database()
    
    # TODO: Implement attack chain detection
    # This will be for Model 6 (LSTM)
    # For now, return empty
    
    logger.info("Attack sequence extraction not implemented yet (Model 6)")
    return []


def save_prophet_training_data(df: pd.DataFrame, filename: str = "models/prophet_training_data.csv"):
    """Save extracted data for Prophet training"""
    df.to_csv(filename, index=False)
    logger.info(f"✅ Saved training data to {filename}")
    logger.info(f"   {len(df)} hourly data points")
    logger.info(f"   {len(df.columns)-2} attack types tracked")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    logger.info("="*60)
    logger.info("DATA EXTRACTION FOR ML MODELS")
    logger.info("="*60)
    
    # Extract Prophet data
    logger.info("\n📥 Extracting hourly attack counts by tactic...")
    df = extract_hourly_attack_counts_by_tactic(months=6)
    
    if len(df) > 0:
        # Save for training
        save_prophet_training_data(df)
        
        logger.info("\n✅ Data extraction complete!")
        logger.info("\nNext steps:")
        logger.info("1. Train Prophet: python train_attack_forecaster.py")
        logger.info("2. Deploy forecaster service")
    else:
        logger.error("\n❌ No data extracted - check MongoDB connection")
