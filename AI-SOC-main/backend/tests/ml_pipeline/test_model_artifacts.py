import pytest
from pathlib import Path
import sys
import numpy as np
import pandas as pd

app_root = Path(__file__).resolve().parents[2]
sys.path.append(str(app_root / "scripts" / "train_models"))

from training_loops.train_anomaly import train_anomaly_detector
from training_loops.train_forecaster import train_forecaster

class TestArtifactExports:

    def test_anomaly_artifact_format_matches_api(self, tmp_path, monkeypatch):
        """Verifies train_anomaly explicitly yields the 4-key dictionary the ML API expects."""
        
        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("training_loops.train_anomaly.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('''
            training:
              sample_fraction: 1.0
              anomaly_detector:
                n_estimators: 2
                contamination: 0.1
            paths:
              wazuh_processed: "processed"
              models_out: "models"
            ''')
            
        feat_dir = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1'
        feat_dir.mkdir(parents=True, exist_ok=True)
        
        pl = pd.DataFrame({
            "timestamp": pd.date_range("2023-01-01", periods=5, freq="h"),
            "agent.ip": ["1.1.1.1"] * 5,
            "total_alerts": [1, 2, 3, 4, 100],
            "severity_peak": [1, 1, 1, 1, 10]
        })
        pl.to_parquet(feat_dir / "behavioral_features_24h.parquet")

        # Run trainer
        train_anomaly_detector(config_path=str(cfg_dir.relative_to(tmp_path / 'mock_root') / "scaling_config.yaml"))
        
        # Verify artifact exists
        models_dir = tmp_path / 'mock_root' / 'models'
        artifact = models_dir / "anomaly_detector.pkl"
        
        assert artifact.exists()
        
        import pickle
        with open(artifact, "rb") as f:
            loaded_dict = pickle.load(f)
            
        assert isinstance(loaded_dict, dict)
        assert "model" in loaded_dict
        assert "scaler" in loaded_dict
        assert "feature_names" in loaded_dict
        assert "trained" in loaded_dict
        assert loaded_dict["trained"] is True
        
        # Verify ML API can actually call the scaler dynamically
        # Simulating anomaly_detector.py API ingest code:
        test_vector = pd.DataFrame({"total_alerts": [5], "severity_peak": [2]})
        scaled_vector = loaded_dict["scaler"].transform(test_vector)
        pred = loaded_dict["model"].predict(scaled_vector)
        assert len(pred) == 1

    def test_lstm_training_smoke_and_e2e_inference(self, tmp_path, monkeypatch):
        """Verifies (11) Minimal Training, (12) Serialization, and (15) End-to-End Inference loading."""
        
        # We need tensorflow for this test, skip gracefully if not installed
        try:
            import tensorflow as tf
            from tensorflow.keras.models import load_model
        except ImportError:
            pytest.skip("TensorFlow not installed. Skipping LSTM End-to-End test.")

        fake_path = tmp_path / 'mock_root' / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("training_loops.train_lstm_stage.Path.resolve", lambda x: fake_path)
        
        cfg_dir = tmp_path / 'mock_root' / 'backend' / 'scripts' / 'train_models' / 'configs'
        cfg_dir.mkdir(parents=True, exist_ok=True)
        
        with open(cfg_dir / "scaling_config.yaml", "w") as f:
            f.write('''
            training:
              sample_fraction: 1.0
              lstm_attack_stage:
                sequence_length: 5
                batch_size: 2
                epochs: 1
            paths:
              models_out: "models"
            ''')
            
        feat_dir = tmp_path / 'mock_root' / 'backend' / 'data' / 'features' / 'v1'
        feat_dir.mkdir(parents=True, exist_ok=True)
        
        # Dummy target sequences matching what SequenceMaker outputs 
        # (10 rows for smoke test, randomly initialized [rule.level, tactic_enum])
        # Note c_sequence_maker exports arrays.
        seq_data = []
        for _ in range(10):
            # A sequence of 5 events, each event has 2 features
            window = [[float(np.random.randint(1,10)), float(np.random.randint(1,14))] for _ in range(5)]
            seq_data.append(window)
            
        pl = pd.DataFrame({
            "sequence_features": seq_data,
            "target_stage": np.random.randint(1, 14, size=10) # Targets 1-14
        })
        pl.to_parquet(feat_dir / "sequence_features.parquet")
        
        # 11: MINIMAL TRAINING SMOKE TEST
        # Instantiate trainer and run 1 epoch on 10 samples
        from training_loops.train_lstm_stage import LSTMTrainer
        trainer = LSTMTrainer(config_path=str(cfg_dir.relative_to(tmp_path / 'mock_root') / "scaling_config.yaml"))
        trainer.train() # This runs pad_and_scale, build_model, fit, and save
        
        # 12: MODEL SERIALIZATION TEST
        models_dir = tmp_path / 'mock_root' / 'models'
        h5_path = models_dir / "attack_stage_lstm.h5"
        pkl_path = models_dir / "attack_stage_lstm_scaler.pkl"
        
        assert h5_path.exists(), "LSTM H5 Serialization failed."
        assert pkl_path.exists(), "Scaler PKL Serialization failed."
        
        # 15: END-TO-END INFERENCE TEST
        # Simulate attack_stage_predictor.py microservice loading logic
        import joblib
        inference_model = load_model(h5_path)
        inference_scaler = joblib.load(pkl_path)
        
        # Generate a dummy incoming Inference sequence (shape matching inference prep)
        # Assuming 1 batch, sequence_length=5, 25 padded features
        raw_inference_input = np.random.rand(1, 5, 25)
        
        # The microservice reshapes to 2D for the scaler, transforms, reshapes back
        flat_input = raw_inference_input.reshape(-1, 25)
        scaled_input = inference_scaler.transform(flat_input)
        final_input_tensor = scaled_input.reshape(-1, 5, 25)
        
        # Inference prediction!
        predictions = inference_model.predict(final_input_tensor, verbose=0)
        
        # Must return exactly 15 classes (14 MITRE + 0)
        assert predictions.shape == (1, 15)
        assert predictions[0].sum() > 0.99 # Softmax valid
