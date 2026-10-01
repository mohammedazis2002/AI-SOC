import logging
import yaml
import pandas as pd
import numpy as np
import multiprocessing as mp
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variable for the worker process to avoid pickling the detector class
global_detector = None

def init_worker(root_dir):
    """Initialize the detector once per worker process to avoid serialization bugs."""
    global global_detector
    import sys
    sys.path.append(str(root_dir))
    from backend.services.ml.anomaly_detection.anomaly_detector import detector
    global_detector = detector

def process_chunk(alerts_chunk):
    """Worker function to process a chunk of alerts"""
    return global_detector.extract_features(alerts_chunk)

def train_anomaly_detector(config_path="backend/scripts/train_models/configs/scaling_config.yaml"):
    root_dir = Path(__file__).resolve().parents[4]
    
    with open(root_dir / config_path, "r") as f:
        config = yaml.safe_load(f)
        
    anom_cfg = config["training"]["anomaly_detector"]
    wazuh_interim = root_dir / config["paths"]["wazuh_interim"]
    models_dir = root_dir / config["paths"]["models_out"]
    models_dir.mkdir(parents=True, exist_ok=True)
    
    parquet_files = list(wazuh_interim.glob("*.parquet"))
    if not parquet_files:
        logger.warning(f"Raw parquet files missing in {wazuh_interim}. Run ingestion pipeline first.")
        return
        
    logger.info("Loading wazuh raw parquet files...")
    df = pd.concat([pd.read_parquet(f) for f in parquet_files], ignore_index=True)
    logger.info(f"Loaded {len(df)} total raw alerts")
    
    logger.info("Extracting 48 features from each raw alert using multiprocessing...")
    
    alerts = df.to_dict('records')
    
    # Clean up massive DataFrame memory to prevent RAM crash before forking
    del df 
    
    # Split alerts into chunks for multiprocessing
    num_cores = max(1, mp.cpu_count() - 1) # leave 1 core free for OS/VS Code
    chunk_size = max(1, len(alerts) // (num_cores * 4))
    chunks = [alerts[i:i + chunk_size] for i in range(0, len(alerts), chunk_size)]
    
    logger.info(f"Splitting {len(alerts)} alerts into {len(chunks)} chunks across {num_cores} CPU cores...")
    
    with mp.Pool(processes=num_cores, initializer=init_worker, initargs=(root_dir,)) as pool:
        # pool.map returns a list of results (each result is a numpy array)
        results = pool.map(process_chunk, chunks)
    
    # Vertically stack the arrays from all workers
    features = np.vstack(results)
    logger.info("Finished multiprocessing extraction!")
    
    X = pd.DataFrame(features)
    logger.info(f"Extracted features shape: {X.shape}")
    
    # 1. Temporal split
    # Get timestamps for sorting
    timestamps = [alert.get('timestamp') for alert in alerts]
    X['timestamp'] = pd.to_datetime(timestamps, format='ISO8601', errors='coerce')
    X = X.sort_values(by="timestamp").reset_index(drop=True)
    X = X.drop(columns=['timestamp'])
    
    split_idx = int(len(X) * 0.8)
    X_train = X.iloc[:split_idx]
    
    sample_frac = config["training"].get("sample_fraction", 1.0)
    if sample_frac < 1.0:
        logger.info(f"Downsampling for matrix size reduction (retention: {sample_frac*100}%)")
        X_train = X_train.sample(frac=sample_frac, random_state=42)
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)
    
    logger.info(f"Fitting IF model on array {X_scaled.shape}...")
    model = IsolationForest(
        n_estimators=anom_cfg["n_estimators"],
        contamination=anom_cfg["contamination"],
        max_samples=anom_cfg.get("max_samples", 256),
        n_jobs=-1,
        random_state=42
    )
    model.fit(X_scaled)
    
    # 2. Extract feature names for API compatibility
    feature_names = detector.feature_names
    
    # 3. Create export dict
    export_dict = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_names,
        'trained': True
    }
    
    out_path = models_dir / "anomaly_detector.pkl"
    with open(out_path, 'wb') as f:
        import pickle
        pickle.dump(export_dict, f)
        
    logger.info(f"Trained IsolationForest explicitly mapped and exported to {out_path}.")

if __name__ == "__main__":
    train_anomaly_detector()
