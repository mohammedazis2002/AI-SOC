import logging

try:
    import polars as pl
except ImportError:
    logging.warning("Polars is not installed. Out-of-core aggregations will fail without it.")

def get_anomaly_feature_aggregations():
    """
    Returns the Polars aggregation logic for behavioral features.
    This logic is strictly used by both the offline `b_feature_builder.py` pipeline 
    and the online streaming engines to ensure identical feature extraction.
    """
    return [
        pl.len().alias("total_alerts"),
        
        # Severity metrics
        pl.col("rule.level").cast(pl.Float64).max().alias("peak_severity"),
        pl.col("rule.level").cast(pl.Float64).mean().alias("avg_severity"),
        
        # Behavioral / Entity metrics (using columns available in real Wazuh data)
        # Real data has agent.id (100%), srcip (92%), dstip (92%) — but NOT username
        pl.col("agent.id").cast(pl.Utf8).n_unique().alias("unique_agents"),
        pl.col("srcip").cast(pl.Utf8).n_unique().alias("unique_sources"),
        pl.col("dstip").cast(pl.Utf8).n_unique().alias("unique_destinations"),
        
        # Heuristics
        (pl.col("rule.id").cast(pl.Utf8).str.contains("1002|5715").sum()).alias("failed_logins_count"),
        (pl.col("rule.id").cast(pl.Utf8).str.contains("5712|5710").sum()).alias("ssh_commands_count"),
        
        # MITRE tactic matching (cast to Utf8 to handle nulls safely)
        (pl.col("rule.mitre.tactic").cast(pl.Utf8).fill_null("unknown").str.to_lowercase().str.contains("reconnaiss|discovery").sum()).alias("scan_activity_count"),
        (pl.col("rule.mitre.tactic").cast(pl.Utf8).fill_null("unknown").str.to_lowercase().str.contains("malware|impact").sum()).alias("malware_detections"),
    ]

def apply_baseline_normalization(df: "pl.LazyFrame") -> "pl.LazyFrame":
    """
    Applies baseline-normalized metrics (converting absolute sums to ratios).
    Ensures that Anomaly Detection models measure deviation, not raw absolute volume.
    """
    # Create baseline normalized features (example: ratio of failed logins to total alerts)
    # Using `total_alerts + 1` to prevent division by zero mathematically.
    return df.with_columns([
        (pl.col("failed_logins_count") / (pl.col("total_alerts") + 1)).alias("failed_login_ratio"),
        (pl.col("unique_sources") / (pl.col("total_alerts") + 1)).alias("unique_ip_ratio"),
        (pl.col("total_alerts") / (pl.col("total_alerts").mean().over("agent.ip") + 1)).alias("alert_rate_ratio"),
    ])
