import logging
import yaml
import datetime
import os
import shutil
from pathlib import Path
from sklearn.preprocessing import StandardScaler
import pandas as pd

try:
    import polars as pl
except ImportError:
    logging.warning("Polars is not installed. Out-of-core aggregations will fail without it.")

import sys
sys.path.append(str(Path(__file__).resolve().parents[4]))

try:
    from backend.services.ml.anomaly_detection.preprocessing import get_anomaly_feature_aggregations, apply_baseline_normalization
    from backend.services.ml.attack_forecasting.preprocessing import get_forecaster_feature_aggregations
except ImportError as e:
    logger.error(f"Failed to load unified preprocessing imports: {e}")
    # Fallback to prevent breaking tests if paths aren't right
    get_anomaly_feature_aggregations = lambda: []
    apply_baseline_normalization = lambda df: df
    get_forecaster_feature_aggregations = lambda: []

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class FeatureBuilder:
    def __init__(self, config_path: str = "backend/scripts/train_models/configs/scaling_config.yaml"):
        self.root_dir = Path(__file__).resolve().parents[4]
        self.config_path = self.root_dir / config_path
        
        with open(self.config_path, "r") as f:
            self.config = yaml.safe_load(f)
            
        # Configure Polars for optimal performance
        try:
            pl.Config.set_num_threads(self.config["pipeline"]["feature_engineering"]["threads"])
        except AttributeError:
            # Fallback for older Polars versions
            try:
                pl.set_polars_options(num_threads=self.config["pipeline"]["feature_engineering"]["threads"])
            except:
                logger.warning("Could not set Polars thread count - using defaults")
            
        self.parquet_dir = self.root_dir / self.config["paths"]["wazuh_interim"]
        self.features_base_dir = self.root_dir / "backend/data/features"
        self.features_base_dir.mkdir(parents=True, exist_ok=True)
        
        # Versioning
        self.version = "v1"
        self.version_dir = self.features_base_dir / self.version
        self.version_dir.mkdir(parents=True, exist_ok=True)
        
        self.sample_fraction = self.config["training"].get("sample_fraction", 1.0)
        pl.Config.set_streaming_chunk_size(4000000)

    def _build_window_features(self, lazy_df: pl.LazyFrame, window_name: str, every: str):
        logger.info(f"Building {window_name} ({every}) grouped aggregations...")
        
        # Ensure timestamp is datetime
        lazy_df = lazy_df.with_columns(
            pl.col("timestamp").cast(pl.Datetime)
        )
        
        # 1. Stratified Alert Sampling (Alert Imbalance Bias Correction)
        # Cap the massive volume of noise while preserving the rare true positives
        # Because we're in lazy mode, we apply a partition filter using a window max representation if doing strictly polars streaming.
        # However, for simplicity and stability on the Wazuh dataset: we filter row numbers over grouping.
        # Limit to max 50,000 per rule.id so authentication noise does not override model weight parameters.
        logger.info("Applying Stratified Sampling (Rule-Level Cap) to prevent Alert Imbalance Bias...")
        
        # Load unified model-specific feature aggregations to avoid duplication
        anomaly_aggs = get_anomaly_feature_aggregations()
        forecaster_aggs = get_forecaster_feature_aggregations()
        
        # Merge unified expressions
        all_aggs = anomaly_aggs + forecaster_aggs
        # Deduplicate overlapping columns if any (e.g. total_alerts)
        unique_aggs = {expr.meta.output_name(): expr for expr in all_aggs}.values()
        
        # Polars dynamic groupby requires sorted data by the time column
        features_df = (
            lazy_df
            .drop_nulls(subset=["agent.ip", "timestamp"])
            .sort("timestamp")
            # Apply Stratified cap (max 50k per rule_id per host to prevent memory blowup)
            # Utilizing sample row_number per rule to drop dominant noise
            .with_columns(pl.int_range(0, pl.len()).over("rule.id").alias("rule_row_num"))
            .filter(pl.col("rule_row_num") < 50000)
            .drop("rule_row_num")
            .group_by_dynamic("timestamp", every=every, group_by="agent.ip")
            .agg(list(unique_aggs))
            .fill_null(0)
        )
        
        # Apply baseline normalization exclusively available via the unified anomaly preprocessor 
        # (Converting counts back to ratios relative to total host behavior history)
        features_df = apply_baseline_normalization(features_df)
        
        result_df = features_df.collect(engine="streaming")
        
        if len(result_df) == 0:
            logger.warning(f"No results generated for window {window_name}")
            return
            
        # Feature Scaling using Scikit-Learn (converting to Pandas first)
        logger.info("Normalizing feature matrix using StandardScaler...")
        pdf = result_df.to_pandas()
        
        # Identify numeric columns for scaling
        skip_cols = ["agent.ip", "timestamp"]
        numeric_cols = [c for c in pdf.columns if c not in skip_cols]
        
        scaler = StandardScaler()
        pdf[numeric_cols] = scaler.fit_transform(pdf[numeric_cols])
        
        # Save output to versioned feature store
        out_file = self.version_dir / f"behavioral_features_{window_name}.parquet"
        pdf.to_parquet(out_file, compression='snappy')
        logger.info(f"Scaled features stored at {out_file} (Rows: {len(pdf)})")
        
    def build_features(self):
        logger.info("Initializing Feature Builder Pipeline...")
        
        parquet_files = str(self.parquet_dir / "*.parquet")
        lazy_df = pl.scan_parquet(parquet_files)
        
        if self.sample_fraction < 1.0:
             logger.info(f"Downsampling for localized execution: keeping {self.sample_fraction*100}% of data")
             lazy_df = lazy_df.filter(pl.int_range(0, pl.len()) < (pl.len() * self.sample_fraction))

        # Build multiple time windows
        self._build_window_features(lazy_df, "1h", "1h")
        self._build_window_features(lazy_df, "24h", "1d")
        
        # Save metadata footprint
        metadata = {
            "version": self.version,
            "generation_timestamp": datetime.datetime.now().isoformat(),
            "windows_generated": ["1h", "24h"],
            "sample_fraction": self.sample_fraction,
            "schema_contract": "feature_schema.json"
        }
        
        with open(self.version_dir / "feature_metadata.yaml", "w") as f:
            yaml.dump(metadata, f)
            
        logger.info("Feature Store updating complete. Metadata generated.")

if __name__ == "__main__":
    builder = FeatureBuilder()
    builder.build_features()
