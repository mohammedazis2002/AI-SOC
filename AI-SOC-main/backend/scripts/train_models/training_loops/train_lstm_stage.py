import logging
import yaml
import os
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout, BatchNormalization
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
except ImportError:
    logging.warning("TensorFlow not detected. Inference endpoints require .h5 artifacts.")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Check GPU availability
gpus = tf.config.list_physical_devices('GPU')
if gpus:
    logger.info(f"✅ Found {len(gpus)} GPU(s): {[gpu.name for gpu in gpus]}")
    try:
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
    except RuntimeError as e:
        logger.warning(f"Memory growth setting failed: {e}")
else:
    logger.warning("⚠️ No GPUs found. Training will use CPU.")

class LSTMTrainer:
    def __init__(self, config_path: str = "backend/scripts/train_models/configs/scaling_config.yaml"):
        self.root_dir = Path(__file__).resolve().parents[4]
        self.config_path = self.root_dir / config_path
        
        with open(self.config_path, "r") as f:
            self.config = yaml.safe_load(f)
            
        self.features_dir = self.root_dir / "backend/data/features/v1"
        self.models_dir = self.root_dir / self.config["paths"]["models_out"]
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # ─── All hyperparameters from config ─────────────────────────────
        self.lstm_cfg = self.config["training"]["lstm_attack_stage"]
        self.seq_len = self.lstm_cfg.get("sequence_length", 50)
        self.batch_size = self.lstm_cfg.get("batch_size", 64)
        self.hidden_size = self.lstm_cfg.get("hidden_size", 256)
        self.num_layers = self.lstm_cfg.get("num_layers", 2)
        self.learning_rate = self.lstm_cfg.get("learning_rate", 0.001)
        self.dropout = self.lstm_cfg.get("dropout", 0.3)
        self.epochs = self.lstm_cfg.get("epochs", 30)
        self.use_amp = self.lstm_cfg.get("use_amp", False)
        
        # Must match lstm_timing_predictor.py and c_sequence_maker.py
        self.num_features = 25
        self.num_classes = 15  # 14 MITRE tactics + 1 unknown
        
        logger.info("─── LSTM Training Configuration ───")
        logger.info(f"  sequence_length: {self.seq_len}")
        logger.info(f"  batch_size:      {self.batch_size}")
        logger.info(f"  hidden_size:     {self.hidden_size}")
        logger.info(f"  num_layers:      {self.num_layers}")
        logger.info(f"  learning_rate:   {self.learning_rate}")
        logger.info(f"  dropout:         {self.dropout}")
        logger.info(f"  epochs:          {self.epochs}")
        logger.info(f"  use_amp:         {self.use_amp}")
        logger.info(f"  num_features:    {self.num_features}")
        logger.info(f"  num_classes:     {self.num_classes}")

    def split_temporally(self, df: pd.DataFrame, train_ratio: float = 0.8):
        """Strict Chronological splitting to eradicate data leakage."""
        logger.info(f"Applying strict {train_ratio*100}% temporal split.")
        
        if 'timestamp' in df.columns:
            df = df.sort_values(by="timestamp").reset_index(drop=True)
            
        split_idx = int(len(df) * train_ratio)
        
        train_df = df.iloc[:split_idx]
        val_df = df.iloc[split_idx:]
        
        return train_df, val_df

    def pad_and_scale_tensors(self, df: pd.DataFrame, is_train: bool = True):
        """Prepare ragged sequences into strictly shaped (batch, seq_len, 25) tensors."""
        X_list = []
        y_list = []
        
        for _, row in df.iterrows():
            seq = row['sequence_features']
            target = row['target_stage']
            
            # Each step should already have 25 features from enriched c_sequence_maker
            # Pad/truncate to exactly 25 as a safety net
            padded_seq = []
            for step in seq:
                step_val = list(step)
                while len(step_val) < self.num_features:
                    step_val.append(0.0)
                padded_seq.append(step_val[:self.num_features])
            
            # Pad timeline to seq_len
            while len(padded_seq) < self.seq_len:
                padded_seq.insert(0, [0.0] * self.num_features)
            
            X_list.append(padded_seq[-self.seq_len:])
            y_list.append(target)
            
        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.int32)
        
        # Flatten -> Scale -> Reshape to ensure identically normalized dimensions
        X_flat = X.reshape(-1, self.num_features)
        
        if is_train:
            self.scaler = StandardScaler()
            X_flat = self.scaler.fit_transform(X_flat)
        else:
            X_flat = self.scaler.transform(X_flat)
            
        X_scaled = X_flat.reshape(-1, self.seq_len, self.num_features)
        return X_scaled, y

    def build_model(self):
        """Build Keras LSTM model dynamically from config parameters."""
        layers = []
        
        # Stack LSTM layers based on num_layers config
        for i in range(self.num_layers):
            is_last_lstm = (i == self.num_layers - 1)
            
            if i == 0:
                # First layer needs input_shape
                layers.append(LSTM(
                    self.hidden_size,
                    return_sequences=not is_last_lstm,
                    input_shape=(self.seq_len, self.num_features)
                ))
            else:
                # Subsequent layers halve the hidden size for a funnel architecture
                layer_size = max(32, self.hidden_size // (2 ** i))
                layers.append(LSTM(
                    layer_size,
                    return_sequences=not is_last_lstm
                ))
            
            layers.append(BatchNormalization())
            layers.append(Dropout(self.dropout))
        
        # Dense head
        layers.append(Dense(max(16, self.hidden_size // (2 ** self.num_layers)), activation='relu'))
        layers.append(Dense(self.num_classes, activation='softmax'))
        
        model = Sequential(layers)
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        logger.info("─── Model Architecture ───")
        model.summary(print_fn=logger.info)
        
        return model

    def train(self):
        data_file = self.features_dir / "sequence_features.parquet"
        if not data_file.exists():
            logger.error(f"Missing File: {data_file}. Run c_sequence_maker.py first.")
            return
            
        logger.info("Loading chronologically ordered sequences into memory...")
        df = pd.read_parquet(data_file)
        
        if len(df) == 0:
            logger.error("Empty dataframe. Dataset is structurally flawed.")
            return

        # 1. Temporal Split
        train_df, val_df = self.split_temporally(df, 0.8)
        
        # 2. Extract and Scale Tensors
        X_train, y_train = self.pad_and_scale_tensors(train_df, is_train=True)
        X_val, y_val = self.pad_and_scale_tensors(val_df, is_train=False)
        
        logger.info(f"Training Tensor Shape: {X_train.shape}")
        logger.info(f"Validation Tensor Shape: {X_val.shape}")
        logger.info(f"Class distribution (train): {np.bincount(y_train, minlength=self.num_classes)}")
        logger.info(f"Class distribution (val):   {np.bincount(y_val, minlength=self.num_classes)}")
        
        # 3. Compile Keras Model (architecture from config)
        model = self.build_model()
        
        callbacks = [
            EarlyStopping(patience=5, restore_best_weights=True, monitor='val_loss'),
            ReduceLROnPlateau(factor=0.5, patience=2, monitor='val_loss')
        ]
        
        # 4. Enable AMP if configured
        if self.use_amp and gpus:
            logger.info("Enabling Automatic Mixed Precision (AMP) for GPU training...")
            tf.keras.mixed_precision.set_global_policy('mixed_float16')
        
        logger.info("Initiating FIT cycle for LSTM Stage Predictor...")
        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            batch_size=self.batch_size,
            epochs=self.epochs,
            callbacks=callbacks,
            verbose=1
        )
        
        # 5. Log final metrics
        final_train_acc = history.history['accuracy'][-1]
        final_val_acc = history.history['val_accuracy'][-1]
        final_val_loss = history.history['val_loss'][-1]
        best_epoch = np.argmin(history.history['val_loss']) + 1
        
        logger.info("─── Training Results ───")
        logger.info(f"  Best epoch:       {best_epoch}")
        logger.info(f"  Train accuracy:   {final_train_acc:.4f}")
        logger.info(f"  Val accuracy:     {final_val_acc:.4f}")
        logger.info(f"  Val loss:         {final_val_loss:.4f}")
        
        # 6. Export artifacts
        model_out = self.models_dir / "attack_stage_lstm.h5"
        scaler_out = self.models_dir / "attack_stage_lstm_scaler.pkl"
        
        model.save(model_out)
        joblib.dump(self.scaler, scaler_out)
        
        logger.info(f"✅ Neural Network saved: {model_out}")
        logger.info(f"✅ Feature Scaler saved: {scaler_out}")

if __name__ == "__main__":
    trainer = LSTMTrainer()
    trainer.train()
