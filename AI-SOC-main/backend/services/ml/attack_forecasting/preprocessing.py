import logging
import pandas as pd

try:
    import polars as pl
except ImportError:
    logging.warning("Polars is not installed. Out-of-core aggregations will fail without it.")

TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access',
    'execution', 'persistence', 'privilege_escalation',
    'defense_evasion', 'credential_access', 'discovery',
    'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact', 'unknown'
]

def get_forecaster_feature_aggregations():
    """
    Returns Polars aggregation logic for attack volume and tactic distribution.
    Used by `b_feature_builder.py` to aggregate the time-series forecasting matrix.
    """
    aggregations = [
        pl.len().alias("total_alerts")
    ]
    
    # Dynamically tracking tactical distributions 
    for tactic in TACTICS:
        aggregations.append(
            (pl.col("rule.mitre.tactic").cast(pl.Utf8).fill_null("unknown").str.to_lowercase() == tactic).sum().alias(tactic)
        )
        
    return aggregations
