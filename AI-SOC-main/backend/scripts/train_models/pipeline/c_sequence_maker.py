import logging
import yaml
import datetime
from pathlib import Path
import pandas as pd
import numpy as np

try:
    import polars as pl
except ImportError:
    logging.warning("Polars is not installed. Out-of-core aggregations will fail without it.")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SequenceMaker:
    """
    Transforms sequential events into chronologically ordered Sliding Windows.
    Extracts 25 features per step aligned with LSTMTimingPredictor.extract_features().
    Generates training examples (sequence_of_events, target_stage).
    """
    TACTICS_MAP = {
        'reconnaissance': 1, 'resource_development': 2, 'initial_access': 3,
        'execution': 4, 'persistence': 5, 'privilege_escalation': 6,
        'defense_evasion': 7, 'credential_access': 8, 'discovery': 9,
        'lateral_movement': 10, 'collection': 11, 'command_and_control': 12,
        'exfiltration': 13, 'impact': 14, 'unknown': 0
    }
    
    # Inverse for quick lookup
    TACTICS_IDX_TO_NAME = {v: k for k, v in TACTICS_MAP.items()}

    # Rule IDs that indicate failed logins (same heuristic as anomaly preprocessing)
    FAILED_LOGIN_RULES = {'1002', '5715'}

    def __init__(self, config_path: str = "backend/scripts/train_models/configs/scaling_config.yaml"):
        self.root_dir = Path(__file__).resolve().parents[4]
        self.config_path = self.root_dir / config_path
        
        with open(self.config_path, "r") as f:
            self.config = yaml.safe_load(f)
            
        # Configure Polars for optimal performance
        try:
            pl.Config.set_num_threads(self.config["pipeline"]["feature_engineering"]["threads"])
        except AttributeError:
            try:
                pl.set_polars_options(num_threads=self.config["pipeline"]["feature_engineering"]["threads"])
            except:
                logger.warning("Could not set Polars thread count - using defaults")
            
        self.parquet_dir = self.root_dir / self.config["paths"]["wazuh_interim"]
        self.features_base_dir = self.root_dir / "backend/data/features"
        self.version_dir = self.features_base_dir / "v1"
        self.version_dir.mkdir(parents=True, exist_ok=True)
        
        lstm_cfg = self.config["training"].get("lstm_attack_stage", {})
        self.seq_len = lstm_cfg.get("sequence_length", 50)
        self.stride = lstm_cfg.get("stride", 1)
        self.max_seqs = lstm_cfg.get("max_sequences_per_host", 1000)
        self.sample_fraction = self.config["training"].get("sample_fraction", 1.0)
        self.num_features = 25  # Must match lstm_timing_predictor.py
        
    def _map_tactic(self, tactic_names):
        """Map MITRE string tactics to integer classifications."""
        if not tactic_names:
            return 0
        if isinstance(tactic_names, list) and len(tactic_names) > 0:
            val = str(tactic_names[0]).lower()
        else:
            val = str(tactic_names).lower()
        
        for k, v in self.TACTICS_MAP.items():
            if k in val:
                return v
        return 0

    def _count_techniques(self, technique_val):
        """Count MITRE techniques from the raw field."""
        if not technique_val or (isinstance(technique_val, float) and np.isnan(technique_val)):
            return 0
        if isinstance(technique_val, list):
            return len(technique_val)
        val = str(technique_val)
        if val in ('None', 'nan', 'null', ''):
            return 0
        # Comma-separated or single value
        return len(val.split(','))

    def _ip_hash_entropy(self, ip_val):
        """Simple hash-based IP entropy matching inference's _calc_ip_entropy."""
        if not ip_val or (isinstance(ip_val, float) and np.isnan(ip_val)):
            return 0.0
        return (hash(str(ip_val)) % 100) / 100.0

    def _is_failed_login(self, rule_id):
        """Check if rule ID indicates a failed login."""
        return str(rule_id).strip() in self.FAILED_LOGIN_RULES

    def _extract_25_features(self, group_df: pd.DataFrame, idx: int):
        """
        Extract 25 features for a single alert step, matching the 
        feature schema in lstm_timing_predictor.py:extract_features().
        
        Features 1-25 align with the inference endpoint's feature order.
        """
        row = group_df.iloc[idx]
        features = []
        
        # 1. Stage number (normalized to 0-1)
        stage_idx = row['stage_idx']
        features.append(stage_idx / 14.0)
        
        # 2. Severity score (rule.level normalized, Wazuh levels 0-15)
        rule_level = float(row.get('rule.level', 5))
        severity_norm = min(rule_level / 15.0, 1.0)
        features.append(severity_norm)
        
        # 3. Time since previous alert (minutes, log-normalized)
        if idx > 0:
            prev_ts = pd.to_datetime(group_df.iloc[idx - 1]['timestamp'])
            curr_ts = pd.to_datetime(row['timestamp'])
            diff_minutes = max(0, (curr_ts - prev_ts).total_seconds() / 60.0)
            features.append(np.log1p(diff_minutes) / 10.0)
        else:
            features.append(0.0)
        
        # 4. Cumulative alert count in sequence (position-based, set during windowing)
        #    Placeholder — will be overwritten during window assembly
        features.append(0.0)
        
        # 5. Alert type encoded (hash of rule.id)
        rule_id = str(row.get('rule.id', 'unknown'))
        features.append((hash(rule_id) % 100) / 100.0)
        
        # 6. Source IP entropy
        features.append(self._ip_hash_entropy(row.get('srcip')))
        
        # 7. Destination IP entropy
        features.append(self._ip_hash_entropy(row.get('dstip')))
        
        # 8. Port diversity (not in Wazuh — default)
        features.append(0.5)
        
        # 9. Protocol type (not in Wazuh — default)
        features.append(0.0)
        
        # 10. Payload size (not in Wazuh — default)
        features.append(0.0)
        
        # 11-12. Hour of day (sin/cos encoded)
        ts = pd.to_datetime(row['timestamp'])
        hour = ts.hour
        features.append(np.sin(2 * np.pi * hour / 24))
        features.append(np.cos(2 * np.pi * hour / 24))
        
        # 13-14. Day of week (sin/cos encoded)
        day = ts.weekday()
        features.append(np.sin(2 * np.pi * day / 7))
        features.append(np.cos(2 * np.pi * day / 7))
        
        # 15. Alert frequency (alerts per hour — computed over window, placeholder)
        features.append(0.0)
        
        # 16. Unique sources count (placeholder — computed over window)
        features.append(0.0)
        
        # 17. Unique destinations count (placeholder — computed over window)
        features.append(0.0)
        
        # 18. Failed/success ratio (placeholder — computed over window)
        features.append(0.0)
        
        # 19. Privilege level (not in Wazuh — default)
        features.append(0.5)
        
        # 20. User type (not in Wazuh — default)
        features.append(0.5)
        
        # 21. Asset criticality (not in Wazuh — default)
        features.append(0.5)
        
        # 22. Network zone (not in Wazuh — default)
        features.append(0.5)
        
        # 23. MITRE technique count (normalized)
        technique_count = self._count_techniques(row.get('rule.mitre.technique'))
        features.append(min(technique_count / 10.0, 1.0))
        
        # 24. Attack momentum (placeholder — computed over window)
        features.append(0.0)
        
        # 25. Lateral movement / Collection / C2 indicator (from tactic)
        tactic_name = self.TACTICS_IDX_TO_NAME.get(stage_idx, 'unknown')
        c2_like = 1.0 if tactic_name in ('lateral_movement', 'collection', 'command_and_control') else 0.0
        features.append(c2_like)
        
        return features

    def _compute_window_features(self, window_features: list, window_df: pd.DataFrame):
        """
        Fill in window-level aggregate features (positions 4, 15-18, 24)
        that require knowing the full window context.
        """
        window_len = len(window_features)
        
        # Time span of window in hours (for alert frequency)
        if window_len >= 2:
            first_ts = pd.to_datetime(window_df.iloc[0]['timestamp'])
            last_ts = pd.to_datetime(window_df.iloc[-1]['timestamp'])
            span_hours = max((last_ts - first_ts).total_seconds() / 3600.0, 1/60)  # min 1 minute
        else:
            span_hours = 1.0
        
        # Unique sources/destinations in window
        unique_src = window_df['srcip'].nunique() if 'srcip' in window_df.columns else 0
        unique_dst = window_df['dstip'].nunique() if 'dstip' in window_df.columns else 0
        
        # Failed login ratio in window
        if 'rule.id' in window_df.columns:
            failed_count = window_df['rule.id'].apply(lambda x: str(x).strip() in self.FAILED_LOGIN_RULES).sum()
            failed_ratio = failed_count / max(len(window_df), 1)
        else:
            failed_ratio = 0.0
        
        # Inter-alert timing for momentum (acceleration)
        if window_len >= 3:
            timestamps = pd.to_datetime(window_df['timestamp'])
            diffs = timestamps.diff().dt.total_seconds().dropna()
            if len(diffs) >= 2:
                # Momentum = are alerts accelerating? (negative diff of diffs = speeding up)
                accel = -np.diff(diffs.values).mean()
                momentum = np.clip(np.tanh(accel / 60.0), -1, 1)  # normalized
            else:
                momentum = 0.0
        else:
            momentum = 0.0
        
        for step_idx in range(window_len):
            feat = window_features[step_idx]
            # 4: Cumulative alert count (position in sequence, normalized)
            feat[3] = (step_idx + 1) / self.seq_len
            # 15: Alert frequency (alerts per hour over window)
            feat[14] = min(window_len / span_hours / 100.0, 1.0)  # normalized
            # 16: Unique sources (normalized)
            feat[15] = min(unique_src / 10.0, 1.0)
            # 17: Unique destinations (normalized)
            feat[16] = min(unique_dst / 10.0, 1.0)
            # 18: Failed/success ratio
            feat[17] = failed_ratio
            # 24: Attack momentum (same for all steps in window)
            feat[23] = (momentum + 1.0) / 2.0  # shift from [-1,1] to [0,1]

    def build_sequences(self):
        logger.info(f"Iterating interim parquets to build {self.seq_len}-step sliding windows...")
        logger.info(f"Extracting {self.num_features} features per step (aligned with inference endpoint)")
        
        # Load interim parquets into a lazy dataframe
        parquet_files = str(self.parquet_dir / "*.parquet")
        lazy_df = pl.scan_parquet(parquet_files)
        
        if self.sample_fraction < 1.0:
            lazy_df = lazy_df.filter(pl.int_range(0, pl.len()) < (pl.len() * self.sample_fraction))
        
        # Project all columns needed for 25-feature extraction
        needed_cols = [
            "timestamp", "agent.ip", "rule.level", "rule.mitre.tactic",
            "rule.mitre.technique", "rule.id", "srcip", "dstip"
        ]
        
        df_sorted = (
            lazy_df
            .select([c for c in needed_cols])
            .drop_nulls(subset=["agent.ip", "timestamp"])
            .with_columns(pl.col("timestamp").cast(pl.Datetime))
            .sort("timestamp")
            .collect(engine="streaming")
        )
        
        pdf = df_sorted.to_pandas()
        grouped = pdf.groupby("agent.ip")
        
        windows = []
        host_count = 0
        
        for host_ip, group in grouped:
            host_count += 1
            if len(group) < 2:
                continue
                
            group = group.sort_values("timestamp").reset_index(drop=True)
            
            # Map tactic labels
            group['stage_idx'] = group['rule.mitre.tactic'].apply(self._map_tactic)
            
            host_seq_count = 0
            
            # Build chronological sliding windows
            for i in range(0, len(group), self.stride):
                if host_seq_count >= self.max_seqs:
                    break
                    
                start_idx = max(0, i - self.seq_len + 1)
                window = group.iloc[start_idx : i + 1]
                
                target = window.iloc[-1]['stage_idx']
                seq_timestamp = window.iloc[-1]['timestamp']
                
                # Extract 25 features for each step in the window
                seq_features = []
                for step_i in range(len(window)):
                    feat = self._extract_25_features(group, start_idx + step_i)
                    seq_features.append(feat)
                
                # Fill in window-level aggregate features
                self._compute_window_features(seq_features, window)
                
                windows.append({
                    "timestamp": seq_timestamp,
                    "host_id": str(host_ip),
                    "sequence_features": seq_features,
                    "sequence_length": len(seq_features),
                    "target_stage": int(target)
                })
                host_seq_count += 1
        
        out_file = self.version_dir / "sequence_features.parquet"
        out_df = pd.DataFrame(windows)
        out_df.to_parquet(out_file, compression='snappy')
        
        logger.info(f"Built {len(out_df)} sliding windows across {host_count} distinct hosts.")
        logger.info(f"Each step contains {self.num_features} features (aligned with inference endpoint).")
        logger.info(f"Sequence matrices serialized to Feature Store -> {out_file}")

if __name__ == "__main__":
    maker = SequenceMaker()
    maker.build_sequences()
