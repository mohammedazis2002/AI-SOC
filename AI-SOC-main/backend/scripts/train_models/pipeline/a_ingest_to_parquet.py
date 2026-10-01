import gzip
import json
import logging
import os
import time
from pathlib import Path
import yaml
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import jsonschema

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DataIngester:
    """
    Streams large compressed `.json.gz` logs out-of-core and converts them
    into optimized Parquet chunks. Target memory usage footprint < 1GB.
    """
    def __init__(self, config_path: str = "backend/scripts/train_models/configs/scaling_config.yaml"):
        # Make paths relative to project root
        self.root_dir = Path(__file__).resolve().parents[4]
        self.config_path = self.root_dir / config_path
        
        with open(self.config_path, "r") as f:
            self.config = yaml.safe_load(f)
            
        self.chunk_size = self.config["pipeline"]["ingestion"]["chunk_size"]
        self.target_cols = self.config["pipeline"]["ingestion"]["target_columns"]
        
        self.raw_dir = self.root_dir / self.config["paths"]["wazuh_raw"]
        self.out_dir = self.root_dir / self.config["paths"]["wazuh_interim"]
        self.out_dir.mkdir(parents=True, exist_ok=True)
        
        schema_path = self.root_dir / "backend/data/schema/alert_schema.json"
        with open(schema_path, "r") as f:
            self.alert_schema = json.load(f)

    def extract_flat_event(self, event: dict) -> dict:
        """Flattens nested Wazuh/Elasticsearch JSON using dot-notation keys defined in config.
        
        Real Wazuh exports from Elasticsearch wrap all data inside '_source'.
        We unwrap that first, then traverse the nested structure.
        """
        # Unwrap Elasticsearch envelope — real data lives inside _source
        source = event.get("_source", event)
        
        flat = {}
        for col in self.target_cols:
            parts = col.split('.')
            val = source
            found = True
            for p in parts:
                if isinstance(val, dict) and p in val:
                    val = val.get(p)
                else:
                    found = False
                    break
            
            if found:
                # Special handling for Mitre items which are often lists
                if isinstance(val, list):
                    val = val[0] if len(val) > 0 else None
                if val is not None:
                    flat[col] = val
        
        # Fallback: use 'location' as agent.ip if agent.ip was not found
        # (real Wazuh data has 'location' on 100% of events vs 4.5% for agent.ip)
        if "agent.ip" not in flat and "location" in source:
            loc = source["location"]
            if isinstance(loc, str):
                flat["agent.ip"] = loc
        
        # Fallback: pull srcip/dstip from nested 'data' object if not found at top level
        if "srcip" not in flat:
            flat["srcip"] = source.get("data", {}).get("srcip")
        if "dstip" not in flat:
            flat["dstip"] = source.get("data", {}).get("dstip")
        
        return flat

    def process_file(self, input_file, chunk_start_idx: int = 0):
        """Process a single .json.gz file. Returns (success, next_chunk_idx).
        input_file can be a Path object or a filename string (resolved relative to raw_dir).
        """
        if isinstance(input_file, str):
            input_file = self.raw_dir / input_file
        if not input_file.exists():
            logger.error(f"Input file not found at {input_file}")
            return False, chunk_start_idx

        logger.info(f"Starting out-of-core streaming ingestion of {input_file} -> {self.out_dir}")
        logger.info(f"Chunk size: {self.chunk_size}")

        chunk_buffer = []
        chunk_idx = chunk_start_idx
        total_rows = 0
        skipped_rows = 0
        start_time = time.time()
        
        try:
            with gzip.open(input_file, 'rt', encoding='utf-8') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        flat_event = self.extract_flat_event(event)
                        
                        # Lightweight required-fields check (replaces slow jsonschema.validate
                        # which is too expensive per-row at 28M+ scale)
                        required_fields = self.alert_schema.get("required", [])
                        missing = [f for f in required_fields if f not in flat_event]
                        if missing:
                            skipped_rows += 1
                            if skipped_rows <= 5:
                                logger.warning(f"Skipping event missing required fields: {missing}")
                            continue

                        chunk_buffer.append(flat_event)
                    except json.JSONDecodeError:
                        skipped_rows += 1
                        continue
                    
                    if len(chunk_buffer) >= self.chunk_size:
                        self._write_chunk(chunk_buffer, chunk_idx)
                        total_rows += len(chunk_buffer)
                        chunk_idx += 1
                        chunk_buffer.clear()
                        
            # Flush remainder
            if chunk_buffer:
                self._write_chunk(chunk_buffer, chunk_idx)
                total_rows += len(chunk_buffer)
                chunk_idx += 1
                
            elapsed = time.time() - start_time
            logger.info(f"Stream complete! Processed {total_rows} rows from {input_file.name} "
                        f"in {elapsed:.2f}s across {chunk_idx - chunk_start_idx} parity chunks.")
            if skipped_rows > 0:
                logger.warning(f"Skipped {skipped_rows} corrupted or malformed lines.")
            return True, chunk_idx
        except Exception as e:
            logger.error(f"Failed to process {input_file}: {e}")
            return False, chunk_idx

    def process_all(self):
        """Auto-discover and process ALL .json.gz files in the raw directory."""
        gz_files = sorted(self.raw_dir.glob("*.json.gz"))
        
        if not gz_files:
            logger.error(f"No .json.gz files found in {self.raw_dir}")
            return False
        
        logger.info(f"Discovered {len(gz_files)} input file(s): {[f.name for f in gz_files]}")
        
        chunk_idx = 0
        total_success = 0
        for gz_file in gz_files:
            success, chunk_idx = self.process_file(gz_file, chunk_start_idx=chunk_idx)
            if success:
                total_success += 1
        
        logger.info(f"Ingestion complete! Successfully processed {total_success}/{len(gz_files)} files "
                     f"into {chunk_idx} total parquet chunks.")
        return total_success == len(gz_files)

    def _write_chunk(self, data: list, idx: int):
        df = pd.DataFrame(data)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        out_file = self.out_dir / f"wazuh_chunk_{idx:04d}.parquet"
        table = pa.Table.from_pandas(df)
        pq.write_table(table, out_file, compression='snappy')
        logger.debug(f"Saved chunk {idx:04d} -> {len(df)} rows.")

if __name__ == "__main__":
    ingester = DataIngester()
    ingester.process_all()
