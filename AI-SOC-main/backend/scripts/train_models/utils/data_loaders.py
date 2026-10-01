import logging
import yaml
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from pathlib import Path

import torch
from torch.utils.data import IterableDataset

logger = logging.getLogger(__name__)

class StreamingParquetDataset(IterableDataset):
    """
    A PyTorch IterableDataset scaling sequentially through chunked Parquet files.
    Allows for deep-learning iteration over 28M rows without triggering OOM on 16GB RAM.
    """
    def __init__(self, parquet_files: list, config_path: str = "backend/scripts/train_models/configs/scaling_config.yaml"):
        super(StreamingParquetDataset).__init__()
        self.parquet_files = parquet_files
        self.root_dir = Path(__file__).resolve().parents[4]
        
        with open(self.root_dir / config_path, "r") as f:
            config = yaml.safe_load(f)
            
        self.seq_len = config["training"]["lstm_attack_stage"]["sequence_length"]
        self.sample_fraction = config["training"]["sample_fraction"]

    def process_chunk(self, df: pd.DataFrame):
        """Converts DataFrames directly into sliced tensor arrays for LSTM consumption."""
        # Simple extraction mapping heuristic features from stage 2 logic
        if 'peak_severity' not in df.columns:
             # Basic fallback if reading raw chunks instead of processed chunks
             df['peak_severity'] = pd.to_numeric(df.get('rule.level', 0), errors='coerce').fillna(0)
             
        features = df[['peak_severity']].to_numpy()
        
        # Sliding windows of seq_len generating consecutive slices
        for i in range(0, len(features) - self.seq_len):
            x = features[i : i + self.seq_len]
            # y represents the numeric predicted "next severity/stage"
            y = features[i + self.seq_len] 
            
            yield torch.tensor(x, dtype=torch.float32), torch.tensor(y, dtype=torch.float32)

    def __iter__(self):
        worker_info = torch.utils.data.get_worker_info()
        
        files_to_process = self.parquet_files
        if worker_info is not None:
            files_to_process = [
                f for i, f in enumerate(self.parquet_files)
                if i % worker_info.num_workers == worker_info.id
            ]
            
        for file in files_to_process:
            try:
                parquet_file = pq.ParquetFile(file)
                # Stream tightly controlled internal batches
                for batch in parquet_file.iter_batches(batch_size=5000):
                    
                    if self.sample_fraction < 1.0:
                        if np.random.rand() > self.sample_fraction:
                            continue
                            
                    df = batch.to_pandas()
                    yield from self.process_chunk(df)
            except Exception as e:
                logger.warning(f"Error streaming {file}: {e}")
                continue
