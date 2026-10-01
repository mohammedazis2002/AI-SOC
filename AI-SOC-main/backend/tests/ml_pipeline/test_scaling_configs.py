import pytest
from pathlib import Path
import sys
import yaml

app_root = Path(__file__).resolve().parents[2]
# Ensure modules are discoverable locally in tests
if str(app_root) not in sys.path:
    sys.path.append(str(app_root))

class TestHardwareScalingConfigurations:
    """Validates the structure of the universal scaling configurations."""

    def test_scaling_config_parsing(self):
        """Verifies the core YAML config is formatted correctly and readable."""
        
        config_path = app_root / "scripts" / "train_models" / "configs" / "scaling_config.yaml"
        assert config_path.exists(), f"Configuration file missing from {config_path}"
        
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
            
        assert "environment" in cfg
        assert "paths" in cfg
        assert "pipeline" in cfg
        assert "training" in cfg
        
        train_cfg = cfg["training"]
        assert "sample_fraction" in train_cfg
        assert "lstm_attack_stage" in train_cfg
        
        # Verify the RT3060 local batch constraints
        lstm_cfg = train_cfg["lstm_attack_stage"]
        assert lstm_cfg["use_amp"] is True, "Mixed precision must be enabled for initial local testing."
        assert lstm_cfg["batch_size"] <= 64, "Initial batch size must accommodate 6GB VRAM bounds."
