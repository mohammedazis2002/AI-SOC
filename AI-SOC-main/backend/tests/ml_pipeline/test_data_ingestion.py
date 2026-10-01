import pytest
from pathlib import Path
import sys
import tempfile
import yaml
import json

app_root = Path(__file__).resolve().parents[2]
# Ensure modules are discoverable locally in tests
sys.path.append(str(app_root / "scripts" / "train_models"))

from pipeline.a_ingest_to_parquet import DataIngester

class TestDataIngestion:

    @pytest.fixture
    def mock_config(self, tmp_path):
        """Creates an ephemeral scaling config block for isolated testing."""
        config_content = {
            "environment": "test_dev",
            "paths": {
                "wazuh_raw": str(tmp_path / "raw"),
                "wazuh_interim": str(tmp_path / "interim"),
                "wazuh_processed": str(tmp_path / "processed"),
                "models_out": str(tmp_path / "models")
            },
            "pipeline": {
                "ingestion": {
                    "chunk_size": 2,
                    "target_columns": ["timestamp", "agent.ip", "rule.level", "rule.mitre.tactic"]
                }
            }
        }
        
        cfg_file = tmp_path / "test_config.yaml"
        with open(cfg_file, "w") as f:
            yaml.dump(config_content, f)
            
        return str(cfg_file)

    def test_ingestion_flattener(self, mock_config, monkeypatch, tmp_path):
        """Validates that deep nested JSON payloads are flattened accurately without RAM explosion."""
        
        # Monkeypatch the root_dir so the ingester utilizes the tmp_path correctly
        monkeypatch.setattr("pipeline.a_ingest_to_parquet.Path.resolve", lambda x: tmp_path)
        
        # Ingester instantiation will use the mock config (the class dynamically prefixes paths)
        # To avoid complex path-patching, we'll directly test the method behavior
        
        class MockIngester(DataIngester):
            def __init__(self, cfg_file):
                with open(cfg_file, "r") as f:
                    self.config = yaml.safe_load(f)
                self.target_cols = self.config["pipeline"]["ingestion"]["target_columns"]
                self.chunk_size = self.config["pipeline"]["ingestion"]["chunk_size"]
        
        ingester = MockIngester(mock_config)
        
        # Emulate complex wazuh message
        raw_event = {
            "timestamp": "2023-10-01T12:00:00Z",
            "agent": {
                "id": "001",
                "ip": "192.168.1.10"
            },
            "rule": {
                "level": 7,
                "mitre": {
                    "tactic": ["Reconnaissance"]
                }
            },
            "unrelated_payload": "BLOB_DATA_TO_BE_DISCARDED"
        }
        
        flat = ingester.extract_flat_event(raw_event)
        
        # Verify nested extraction
        assert flat["agent.ip"] == "192.168.1.10"
        assert flat["rule.level"] == 7
        
        # Verify list flattening
        assert flat["rule.mitre.tactic"] == "Reconnaissance"
        
        # Verify heavy bloat was dropped
        assert "unrelated_payload" not in flat

    def test_process_file_and_chunking(self, mock_config, tmp_path, monkeypatch):
        """Tests reading a gzipped json file and producing snappy compressed parquet chunks."""
        # a_ingest_to_parquet.py uses Path(__file__).resolve().parents[4] -> we need parents[4] to be tmp_path
        fake_path = tmp_path / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.a_ingest_to_parquet.Path.resolve", lambda x: fake_path)
        
        cfg_path = tmp_path / "test_config.yaml"
        # Recreate similar to mock_config but need actual dir paths
        with open(mock_config, "w") as f:
            yaml.dump({
                "environment": "test_dev",
                "paths": {
                    "wazuh_raw": "raw",
                    "wazuh_interim": "interim",
                    "wazuh_processed": "processed"
                },
                "pipeline": {
                    "ingestion": {
                        "chunk_size": 2,
                        "target_columns": ["timestamp", "agent.ip", "rule.level"]
                    }
                }
            }, f)
            
        raw_dir = tmp_path / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        interim_dir = tmp_path / "interim"
        interim_dir.mkdir(parents=True, exist_ok=True)
        
        # Ingester explicitly loads this path off root_dir:
        schema_dir = tmp_path / "backend" / "data" / "schema"
        schema_dir.mkdir(parents=True, exist_ok=True)
        with open(schema_dir / "alert_schema.json", "w") as f:
            f.write('''{
                "type": "object",
                "required": ["timestamp", "agent.ip", "rule.level"]
            }''')

        events = [
            json.dumps({"timestamp": "2023-10-01T12:00:00Z", "agent": {"ip": "1.1.1.1"}, "rule": {"level": 3}}),
            json.dumps({"timestamp": "2023-10-01T12:05:00Z", "agent": {"ip": "1.1.1.2"}, "rule": {"level": 5}}),
            json.dumps({"timestamp": "2023-10-01T12:10:00Z", "agent": {"ip": "1.1.1.3"}, "rule": {"level": 7}})
        ]
        
        test_file = raw_dir / "test_logs.json.gz"
        import gzip
        with gzip.open(test_file, 'wt', encoding='utf-8') as f:
            for event in events:
                f.write(event + "\n")
            f.write("invalid json blob\n") # test error handling

        # Instantiate real ingester with the patched path
        # It reads from tmp_path / "raw" / "test_config.yaml" since root_dir resolves to tmp_path
        ingester = DataIngester(config_path="test_config.yaml")
        
        # Act
        result, _ = ingester.process_file("test_logs.json.gz")
        
        # Assert
        assert result is True
        
        import pyarrow.parquet as pq
        parquets = list(interim_dir.glob("*.parquet"))
        assert len(parquets) == 2 # 3 valid events with chunk size 2 = 2 chunks
        
        # Verify first chunk
        chunk_0 = pq.read_table(interim_dir / "wazuh_chunk_0000.parquet").to_pandas()
        assert len(chunk_0) == 2
        assert chunk_0.iloc[0]["agent.ip"] == "1.1.1.1"
        assert chunk_0.iloc[1]["agent.ip"] == "1.1.1.2"
        
        # Verify second chunk
        chunk_1 = pq.read_table(interim_dir / "wazuh_chunk_0001.parquet").to_pandas()
        assert len(chunk_1) == 1
        assert chunk_1.iloc[0]["agent.ip"] == "1.1.1.3"

    def test_schema_corruption_prevention(self, mock_config, tmp_path, monkeypatch, caplog):
        """Validates that missing required schema fields result in the streaming json skipping the line safely."""
        fake_path = tmp_path / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.a_ingest_to_parquet.Path.resolve", lambda x: fake_path)
        
        cfg_path = tmp_path / "test_config.yaml"
        with open(mock_config, "w") as f:
            yaml.dump({
                "environment": "test_dev",
                "paths": {
                    "wazuh_raw": "raw", "wazuh_interim": "interim", "wazuh_processed": "processed"
                },
                "pipeline": {"ingestion": {"chunk_size": 2, "target_columns": ["timestamp", "agent.ip", "rule.level", "rule.mitre.tactic"]}}
            }, f)
            
        (tmp_path / "raw").mkdir(parents=True, exist_ok=True)
        (tmp_path / "interim").mkdir(parents=True, exist_ok=True)
        schema_dir = tmp_path / "backend" / "data" / "schema"
        schema_dir.mkdir(parents=True, exist_ok=True)

        with open(schema_dir / "alert_schema.json", "w") as f:
            f.write('''{
                "type": "object",
                "required": ["timestamp", "agent.ip", "rule.level"]
            }''')

        events = [
            json.dumps({"timestamp": "2023-01-01T12:00:00Z", "agent": {"ip": "1.1.1.1"}, "rule": {"level": 3}}), # Valid
            json.dumps({"agent": {"ip": "1.1.1.2"}, "rule": {"level": 5}}), # MISSING TIMESTAMP (Corrupt)
            json.dumps({"timestamp": "2023-01-01T12:05:00Z", "rule": {"level": 7}}) # MISSING IP (Corrupt)
        ]
        
        test_file = tmp_path / "raw" / "test_schema.json.gz"
        import gzip
        with gzip.open(test_file, 'wt', encoding='utf-8') as f:
            for event in events:
                f.write(event + "\n")

        ingester = DataIngester(config_path="test_config.yaml")
        ingester.process_file("test_schema.json.gz")
        
        import pyarrow.parquet as pq
        # Should only write 1 valid event, not chunked because size is 2, flushing on exit
        chunk_0 = pq.read_table(tmp_path / "interim" / "wazuh_chunk_0000.parquet").to_pandas()
        
        assert len(chunk_0) == 1
        assert "Skipped 2 corrupted or malformed lines." in caplog.text

    def test_corrupt_json_line_skipped(self, mock_config, tmp_path, monkeypatch, caplog):
        """Verifies ingestion does not crash on malformed JSON logs and continues."""
        fake_path = tmp_path / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.a_ingest_to_parquet.Path.resolve", lambda x: fake_path)
        
        cfg_path = tmp_path / "test_config.yaml"
        with open(mock_config, "w") as f:
            yaml.dump({
                "environment": "test_dev",
                "paths": {"wazuh_raw": "raw", "wazuh_interim": "interim", "wazuh_processed": "processed"},
                "pipeline": {"ingestion": {"chunk_size": 2, "target_columns": ["timestamp", "agent.ip", "rule.level"]}}
            }, f)
            
        (tmp_path / "raw").mkdir(parents=True, exist_ok=True)
        (tmp_path / "interim").mkdir(parents=True, exist_ok=True)
        schema_dir = tmp_path / "backend" / "data" / "schema"
        schema_dir.mkdir(parents=True, exist_ok=True)
        with open(schema_dir / "alert_schema.json", "w") as f:
            f.write('{"type": "object", "required": ["timestamp"]}')

        test_file = tmp_path / "raw" / "test_corrupt.json.gz"
        import gzip
        with gzip.open(test_file, 'wt', encoding='utf-8') as f:
            f.write('{"timestamp": "2023-01-01T12:00:00Z"}\n') # valid
            f.write('{"timestamp":"2024-01-01","agent.ip":"10.0.0.5"\n') # Missing closing brace
            f.write('{"timestamp": "2023-01-01T12:05:00Z"}\n') # valid

        ingester = DataIngester(config_path="test_config.yaml")
        result, _ = ingester.process_file("test_corrupt.json.gz")
        
        import pyarrow.parquet as pq
        chunk_0 = pq.read_table(tmp_path / "interim" / "wazuh_chunk_0000.parquet").to_pandas()
        
        assert result is True
        assert len(chunk_0) == 2 # Only the 2 valid lines
        assert "Skipped 1 corrupted or malformed lines." in caplog.text

    def test_chunk_boundary_integrity(self, mock_config, tmp_path, monkeypatch):
        """Verifies that chunking logic does not lose events on boundaries."""
        fake_path = tmp_path / '1' / '2' / '3' / '4' / 'fake.py'
        monkeypatch.setattr("pipeline.a_ingest_to_parquet.Path.resolve", lambda x: fake_path)
        
        cfg_path = tmp_path / "test_config.yaml"
        # Set chunk size to 3. Input 4 rows. Expect chunk_0=3, chunk_1=1
        with open(mock_config, "w") as f:
            yaml.dump({
                "environment": "test_dev",
                "paths": {"wazuh_raw": "raw", "wazuh_interim": "interim", "wazuh_processed": "processed"},
                "pipeline": {"ingestion": {"chunk_size": 3, "target_columns": ["timestamp"]}}
            }, f)
            
        (tmp_path / "raw").mkdir(parents=True, exist_ok=True)
        (tmp_path / "interim").mkdir(parents=True, exist_ok=True)
        schema_dir = tmp_path / "backend" / "data" / "schema"
        schema_dir.mkdir(parents=True, exist_ok=True)
        with open(schema_dir / "alert_schema.json", "w") as f:
            f.write('{"type": "object", "required": ["timestamp"]}')

        test_file = tmp_path / "raw" / "test_boundary.json.gz"
        import gzip
        with gzip.open(test_file, 'wt', encoding='utf-8') as f:
            for i in range(4):
                f.write('{"timestamp": "2023-01-01T12:00:00Z"}\n')

        ingester = DataIngester(config_path="test_config.yaml")
        ingester.process_file("test_boundary.json.gz")
        
        import pyarrow.parquet as pq
        chunk_0 = pq.read_table(tmp_path / "interim" / "wazuh_chunk_0000.parquet").to_pandas()
        chunk_1 = pq.read_table(tmp_path / "interim" / "wazuh_chunk_0001.parquet").to_pandas()
        
        assert len(chunk_0) == 3
        assert len(chunk_1) == 1
