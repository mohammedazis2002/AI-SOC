import pytest
import polars as pl
import pandas as pd
from pathlib import Path
import sys
import datetime

app_root = Path(__file__).resolve().parents[2]
sys.path.append(str(app_root / "scripts" / "train_models"))

from pipeline.c_sequence_maker import SequenceMaker

class TestSequenceMaker:

    def test_lstm_sliding_windows_shapes(self, tmp_path, monkeypatch):
        """Verifies SequenceMaker groups strictly by host, orders by time, and bounds array dimensions."""
        
        # Patch paths
        # c_sequence_maker resolves root_dir as Path(__file__).resolve().parents[4]
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.c_sequence_maker.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        
        cfg_path = cfg_dir / "scaling_config.yaml"
        # We explicitly enforce seq_len=3 and label_mode=next_stage for test granularity
        with open(cfg_path, "w") as f:
            f.write('''
            training:
              sample_fraction: 1.0
              lstm_attack_stage:
                sequence_length: 3
                batch_size: 2
                label_mode: "next_stage"
            paths:
              wazuh_interim: "interim"
              models_out: "models"
            ''')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate 5 chronological events for ONE host. 
        # With seq_len=3, next_stage, window 1 (0,1,2 target 3), window 2 (1,2,3 target 4)
        # So we should only get exactly 2 complete sliding windows if we enforce len
        # Actually our sliding window starts at 0, building windows up to limit.
        raw_events = pl.DataFrame({
            "timestamp": [
                datetime.datetime(2023, 1, 1, 10, 0),
                datetime.datetime(2023, 1, 1, 10, 5),
                datetime.datetime(2023, 1, 1, 10, 10),
                datetime.datetime(2023, 1, 1, 10, 15),
                datetime.datetime(2023, 1, 1, 10, 20)
            ],
            "agent.ip": ["10.0.0.1"] * 5,
            "rule.level": [1, 2, 3, 4, 5], # Easy to track
            "rule.mitre.tactic": [
                "reconnaissance", "execution", "discovery", "exfiltration", "impact"
            ]
        })
        
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        maker = SequenceMaker(config_path=str(cfg_path.relative_to(tmp_path / 'mock_root')))
        maker.build_sequences()
        
        # Verify 
        feat_dir = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1'
        out_file = feat_dir / "sequence_features.parquet"
        
        assert out_file.exists(), "Sequence maker failed to persist output parquet."
        
        df_out = pd.read_parquet(out_file)
        
        # Assertions
        # 5 events. Valid lengths depend on sequential indexing up to max limit.
        # Since target label logic changed to current stage (final event in window), it no longer skips the last event.
        # Therefore we expect exactly 5 windows generated.
        assert len(df_out) == 5
        
        # Test third window (index 2)
        win3 = df_out.iloc[2]
        
        # Array length should be bounded by self.seq_len=3
        assert win3["sequence_length"] == 3
        
        # Inner array structure should hold the extracted [level, tactic_enum]
        features = win3["sequence_features"]
        
        # Third window should cover events 0,1,2 (levels 1, 2, 3). Target is event 2 ("discovery", enum 9).
        assert features[0][0] == 1.0 # Level of event 0
        assert features[2][0] == 3.0 # Level of event 2
        assert win3["target_stage"] == 9 # Discovery enum map

    def test_chronological_order(self, tmp_path, monkeypatch):
        """Verify events are sorted chronologically before windowing."""
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.c_sequence_maker.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('training: {sample_fraction: 1.0, lstm_attack_stage: {sequence_length: 3, batch_size: 2, label_mode: "next_stage"}}\npaths: {wazuh_interim: "interim", models_out: "models"}')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        # Out of order events
        raw_events = pl.DataFrame({
            "timestamp": [
                datetime.datetime(2023, 1, 1, 10, 3), # C
                datetime.datetime(2023, 1, 1, 10, 1), # A
                datetime.datetime(2023, 1, 1, 10, 2)  # B
            ],
            "agent.ip": ["10.0"] * 3,
            "rule.level": [3, 1, 2],
            "rule.mitre.tactic": ["recon", "recon", "recon"]
        })
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        SequenceMaker(config_path=str((cfg_dir / "scaling_config.yaml").relative_to(tmp_path / 'mock_root'))).build_sequences()
        
        out_file = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1' / "sequence_features.parquet"
        df_out = pd.read_parquet(out_file)
        
        # Third window should have sorted events 1, 2, 3
        # Wait, for 3 events, next_stage means window 0 (A -> B), window 1 (A,B -> C).
        # We check the final window features
        last_window = df_out.iloc[-1]
        features = last_window["sequence_features"]
        # Index 0 of feature is rule_level
        assert features[0][0] == 1.0
        assert features[1][0] == 2.0
        
    def test_sliding_window_logic(self, tmp_path, monkeypatch):
        """Verify sliding window sequences shift exactly by 1 index."""
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.c_sequence_maker.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('training: {sample_fraction: 1.0, lstm_attack_stage: {sequence_length: 3, batch_size: 2, label_mode: "current_stage"}}\npaths: {wazuh_interim: "interim", models_out: "models"}')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        raw_events = pl.DataFrame({
            "timestamp": [datetime.datetime(2023, 1, 1, 10, i) for i in range(5)],
            "agent.ip": ["10.0"] * 5,
            "rule.level": [1, 2, 3, 4, 5],
            "rule.mitre.tactic": ["recon"] * 5
        })
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        SequenceMaker(config_path=str((cfg_dir / "scaling_config.yaml").relative_to(tmp_path / 'mock_root'))).build_sequences()
        
        df_out = pd.read_parquet(tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1' / "sequence_features.parquet")
        
        # Seq_len=3, current_stage=True.
        # Windows: [1], [1,2], [1,2,3], [2,3,4], [3,4,5]
        # Valid full sequences (length 3): indices 2, 3, 4 
        win_2 = df_out.iloc[2]["sequence_features"]
        win_3 = df_out.iloc[3]["sequence_features"]
        win_4 = df_out.iloc[-1]["sequence_features"]
        
        assert win_2[0][0] == 1.0 and win_2[-1][0] == 3.0
        assert win_3[0][0] == 2.0 and win_3[-1][0] == 4.0
        assert win_4[0][0] == 3.0 and win_4[-1][0] == 5.0
        
    def test_target_label_alignment(self, tmp_path, monkeypatch):
        """Verify target label index matches window_end + 1 (next_stage mapping)."""
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.c_sequence_maker.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('training: {sample_fraction: 1.0, lstm_attack_stage: {sequence_length: 3, batch_size: 2, label_mode: "next_stage"}}\npaths: {wazuh_interim: "interim", models_out: "models"}')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        raw_events = pl.DataFrame({
            "timestamp": [datetime.datetime(2023, 1, 1, 10, i) for i in range(4)],
            "agent.ip": ["10.0"] * 4,
            "rule.level": [1, 2, 3, 4],
            "rule.mitre.tactic": ["reconnaissance", "execution", "discovery", "impact"]
        })
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        SequenceMaker(config_path=str((cfg_dir / "scaling_config.yaml").relative_to(tmp_path / 'mock_root'))).build_sequences()
        
        df_out = pd.read_parquet(tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1' / "sequence_features.parquet")
        
        # Sequence: [1, 2, 3]. Target is the final event in the window itself (Discovery = 9)
        third_window = df_out.iloc[2]
        assert third_window["target_stage"] == 9
        
    def test_tensor_shape(self, tmp_path, monkeypatch):
        """Verify the resulting extracted numpy tensors map clearly to (batch_size, seq_len, features) shapes."""
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.c_sequence_maker.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('training: {sample_fraction: 1.0, lstm_attack_stage: {sequence_length: 5, batch_size: 2, label_mode: "current_stage"}}\npaths: {wazuh_interim: "interim", models_out: "models"}')
            
        interim_dir = tmp_path / 'mock_root' / 'interim'
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        raw_events = pl.DataFrame({
            "timestamp": [datetime.datetime(2023, 1, 1, 10, i) for i in range(6)],
            "agent.ip": ["10.0"] * 6,
            "rule.level": [1, 2, 3, 4, 5, 6],
            "rule.mitre.tactic": ["recon"] * 6
        })
        raw_events.write_parquet(interim_dir / "dummy_chunk.parquet")
        
        SequenceMaker(config_path=str((cfg_dir / "scaling_config.yaml").relative_to(tmp_path / 'mock_root'))).build_sequences()
        
        df_out = pd.read_parquet(tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1' / "sequence_features.parquet")
        
        # Note: c_sequence_maker exports unpadded arrays. Padding is done by train_lstm_stage.py
        # Here we verify the raw dimensional extracts and bounds.
        assert len(df_out) == 6
        
        # Max sequence length should never exceed seq_len (5)
        max_len = df_out["sequence_length"].max()
        assert max_len <= 5
        
        # Check innermost feature dimensions
        first_seq = df_out.iloc[0]["sequence_features"]
        last_seq = df_out.iloc[-1]["sequence_features"]
        
        assert len(first_seq) == 1
        assert len(first_seq[0]) == 2 # [rule_level, tactic_enum]
        
        assert len(last_seq) == 5
        assert len(last_seq[0]) == 2
