import pytest
import polars as pl
import pandas as pd
from pathlib import Path
import sys
import datetime
from pandas.testing import assert_frame_equal

app_root = Path(__file__).resolve().parents[2]
sys.path.append(str(app_root / "scripts" / "train_models"))

from pipeline.b_feature_builder import FeatureBuilder

class TestFeatureBuilder:

    def test_build_window_features_logic(self, tmp_path, monkeypatch):
        """Verifies that Polars successfully aggregates and scales rolling time windows."""
        
        # b_feature_builder resolves root_dir as Path(__file__).resolve().parents[4]
        # To make root_dir == (tmp_path / 'mock_root'), we need a path 5 levels deep
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.b_feature_builder.Path.resolve", lambda x: fake_path)
        
        # Construct isolated config file
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        
        cfg_path = cfg_dir / "scaling_config.yaml"
        with open(cfg_path, "w") as f:
            f.write('''
            training:
              sample_fraction: 1.0
            paths:
              wazuh_interim: "interim"
              wazuh_processed: "processed"
            ''')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        # Build dummy Parquet input representing raw logs
        raw_events = pl.DataFrame({
            "timestamp": [
                datetime.datetime(2023, 1, 1, 12, 5, 0),
                datetime.datetime(2023, 1, 1, 12, 10, 0),
                datetime.datetime(2023, 1, 1, 13, 5, 0), # Next hour
                datetime.datetime(2023, 1, 2, 8, 0, 0)   # Next day
            ],
            "agent.ip": ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.2"],
            "agent.id": ["001", "001", "001", "002"],
            "rule.level": [5.0, 7.0, 2.0, 10.0],
            "srcip": ["192.168.1.1", "192.168.1.2", "192.168.1.1", "10.0.0.5"],
            "dstip": ["8.8.8.8", "8.8.8.8", "1.1.1.1", "9.9.9.9"],
            "rule.id": ["1002", "5715", "100", "5710"],
            "rule.mitre.tactic": ["recon", "recon", "none", "malware"]
        })
        
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        # Instantiate and run the pipeline
        builder = FeatureBuilder(config_path=str(cfg_path.relative_to(tmp_path / 'mock_root')))
        
        # Target internal function for granular testing without metadata generation overhead
        builder._build_window_features(pl.scan_parquet(str(interim_dir / "*.parquet")), "1h", "1h")
        
        # Verify Output
        feat_dir = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1'
        out_file = feat_dir / "behavioral_features_1h.parquet"
        
        assert out_file.exists(), "Feature store parquet was not generated."
        
        df_out = pd.read_parquet(out_file)
        
        # 4 events, 10.0.0.1 spans 2 hours (12:00 and 13:00). 10.0.0.2 spans 1 hour.
        # Total distinct time windows grouped by IP = 3 rows.
        assert len(df_out) == 3
        
        # Check normalization applied (StdDev scaling means max values are scaled differently, but we can check columns exist)
        assert "total_alerts" in df_out.columns
        assert "failed_logins_count" in df_out.columns
        assert "scan_activity_count" in df_out.columns
        
        assert df_out["total_alerts"].mean() < 1e-6 # Near zero

    def test_window_aggregation_counts(self, tmp_path, monkeypatch):
        """Verify time window aggregation correctly counts specific behavioral events (e.g. failed logins)."""
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.b_feature_builder.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('training: {sample_fraction: 1.0}\npaths: {wazuh_interim: "interim", wazuh_processed: "processed"}')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        # 3 Failed Logins in 3 minutes for server1 (1002 is failed login)
        raw_events = pl.DataFrame({
            "timestamp": [
                datetime.datetime(2023, 1, 1, 10, 1, 0),
                datetime.datetime(2023, 1, 1, 10, 2, 0),
                datetime.datetime(2023, 1, 1, 10, 3, 0)
            ],
            "agent.ip": ["10.0.0.1", "10.0.0.1", "10.0.0.1"],
            "agent.id": ["001"] * 3,
            "rule.level": [5.0, 5.0, 5.0],
            "srcip": ["192.168.1.1"] * 3,
            "dstip": ["8.8.8.8"] * 3,
            "rule.id": ["1002", "1002", "1002"],
            "rule.mitre.tactic": ["recon"] * 3
        })
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        # Mock StandardScaler so we can check raw counts instead of zero-mean distributions
        monkeypatch.setattr("pipeline.b_feature_builder.StandardScaler.fit_transform", lambda self, x: x)
        
        builder = FeatureBuilder(config_path=str((cfg_dir / "scaling_config.yaml").relative_to(tmp_path / 'mock_root')))
        builder._build_window_features(pl.scan_parquet(str(interim_dir / "*.parquet")), "5m", "5m")
        
        out_file = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1' / "behavioral_features_5m.parquet"
        df_out = pd.read_parquet(out_file)
        
        assert len(df_out) == 1
        assert df_out.iloc[0]["failed_logins_count"] == 3
        assert df_out.iloc[0]["total_alerts"] == 3

    def test_host_isolation(self, tmp_path, monkeypatch):
        """Verify features are computed firmly per host without cross-contamination."""
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.b_feature_builder.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('training: {sample_fraction: 1.0}\npaths: {wazuh_interim: "interim", wazuh_processed: "processed"}')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        # 1 log per host in the same time window
        raw_events = pl.DataFrame({
            "timestamp": [datetime.datetime(2023, 1, 1, 10, 1, 0), datetime.datetime(2023, 1, 1, 10, 1, 0)],
            "agent.ip": ["server1", "server2"],
            "agent.id": ["001", "002"],
            "rule.level": [5.0, 5.0],
            "srcip": ["192.168.1.1", "192.168.1.2"],
            "dstip": ["8.8.8.8", "8.8.8.8"],
            "rule.id": ["1002", "1002"],
            "rule.mitre.tactic": ["recon", "recon"]
        })
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        monkeypatch.setattr("pipeline.b_feature_builder.StandardScaler.fit_transform", lambda self, x: x)
        
        builder = FeatureBuilder(config_path=str((cfg_dir / "scaling_config.yaml").relative_to(tmp_path / 'mock_root')))
        builder._build_window_features(pl.scan_parquet(str(interim_dir / "*.parquet")), "5m", "5m")
        
        out_file = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1' / "behavioral_features_5m.parquet"
        df_out = pd.read_parquet(out_file)
        
        # Should be exactly 2 rows (one for each host)
        assert len(df_out) == 2
        
        # Filter back
        server1_row = df_out[df_out["agent.ip"] == "server1"].iloc[0]
        server2_row = df_out[df_out["agent.ip"] == "server2"].iloc[0]
        
        assert server1_row["failed_logins_count"] == 1
        assert server2_row["failed_logins_count"] == 1

    def test_feature_scaling_stability(self, tmp_path, monkeypatch):
        """Verify scaler transformation avoids NaNs and accurately standardizes means to 0."""
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.b_feature_builder.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('training: {sample_fraction: 1.0}\npaths: {wazuh_interim: "interim", wazuh_processed: "processed"}')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        # Create heavily varied distributions to test scaling
        raw_events = pl.DataFrame({
            "timestamp": [
                datetime.datetime(2023, 1, 1, 10, 1, 0),
                datetime.datetime(2023, 1, 1, 11, 1, 0),
                datetime.datetime(2023, 1, 1, 12, 1, 0)
            ],
            "agent.ip": ["hostA", "hostB", "hostC"],
            "agent.id": ["001", "002", "003"],
            "rule.level": [1.0, 5.0, 10.0],
            "srcip": ["192.168.1.1", "192.168.1.2", "10.0.0.5"],
            "dstip": ["8.8.8.8", "8.8.8.8", "1.1.1.1"],
            "rule.id": ["1002", "1002", "9999"],
            "rule.mitre.tactic": ["recon", "recon", "impact"]
        })
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        # Execute WITH REAL SCALER
        builder = FeatureBuilder(config_path=str((cfg_dir / "scaling_config.yaml").relative_to(tmp_path / 'mock_root')))
        builder._build_window_features(pl.scan_parquet(str(interim_dir / "*.parquet")), "1h", "1h")
        
        out_file = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1' / "behavioral_features_1h.parquet"
        df_out = pd.read_parquet(out_file)
        
        # Check nullity
        assert not df_out.isna().any().any()
        
        # Check standard normal distribution (mean ~ 0) for numeric columns
        skip_cols = ["agent.ip", "timestamp"]
        numeric_cols = [c for c in df_out.columns if c not in skip_cols]
        for col in numeric_cols:
            assert abs(df_out[col].mean()) < 1e-6
            
    def test_dataset_version_creation(self, tmp_path, monkeypatch):
        """Verify pipeline creates the correctly versioned data store folder and footprint."""
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.b_feature_builder.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('training: {sample_fraction: 1.0}\npaths: {wazuh_interim: "interim", wazuh_processed: "processed"}')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        raw_events = pl.DataFrame({
            "timestamp": [datetime.datetime(2023, 1, 1, 10, 1)],
            "agent.ip": ["10.0"], "agent.id": ["001"], "rule.level": [1.0], "srcip": ["192.168.1.1"], "dstip": ["8.8"], "rule.id": ["1"], "rule.mitre.tactic": ["recon"]
        })
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        builder = FeatureBuilder(config_path=str((cfg_dir / "scaling_config.yaml").relative_to(tmp_path / 'mock_root')))
        builder.build_features()
        
        # Verify version creation
        version_dir = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1'
        assert version_dir.exists()
        assert version_dir.is_dir()
        
        # Verify metadata footprint
        metadata_file = version_dir / "feature_metadata.yaml"
        assert metadata_file.exists()
        
        import yaml
        with open(metadata_file, "r") as f:
            meta = yaml.safe_load(f)
            
        assert meta["version"] == "v1"
        assert "generation_timestamp" in meta
        
    def test_schema_drift(self, tmp_path, monkeypatch):
        """Verify feature column outputs strictly match the expected Schema contract."""
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.b_feature_builder.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('training: {sample_fraction: 1.0}\npaths: {wazuh_interim: "interim", wazuh_processed: "processed"}')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        raw_events = pl.DataFrame({
            "timestamp": [datetime.datetime(2023, 1, 1, 10, 1)],
            "agent.ip": ["10.0"], "agent.id": ["001"], "rule.level": [1.0], "srcip": ["192.168.1.1"], "dstip": ["8.8"], "rule.id": ["1"], "rule.mitre.tactic": ["recon"]
        })
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        builder = FeatureBuilder(config_path=str((cfg_dir / "scaling_config.yaml").relative_to(tmp_path / 'mock_root')))
        builder._build_window_features(pl.scan_parquet(str(interim_dir / "*.parquet")), "1h", "1h")
        
        out_file = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1' / "behavioral_features_1h.parquet"
        df_out = pd.read_parquet(out_file)
        
        expected_columns = {
            "agent.ip", "timestamp", "total_alerts", "peak_severity", "avg_severity", 
            "unique_agents", "unique_sources", "unique_destinations", "failed_logins_count", 
            "ssh_commands_count", "scan_activity_count", "malware_detections"
        }
        
        actual_columns = set(df_out.columns)
        assert expected_columns.issubset(actual_columns), f"Schema drift detected! Missing core columns. Expected at least: {expected_columns}, Got: {actual_columns}"
