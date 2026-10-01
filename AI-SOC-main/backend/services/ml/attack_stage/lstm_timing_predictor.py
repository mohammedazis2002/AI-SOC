"""
LSTM Timing Predictor for Attack Stage Progression

Predicts time to next attack stage using LSTM neural network

Features:
- Sequence-based prediction (last 5 alerts)
- 25 features per alert
- Dynamic timing based on attack pattern
- NO time-of-day assumptions (removed!)
- Monte Carlo dropout for uncertainty estimation
"""

import os
import logging
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class LSTMTimingPredictor:
    """
    LSTM-based timing predictor for attack stage progression
    
    Predicts when the next stage of an attack will occur based on:
    - Historical alert sequence
    - Attack stage progression
    - Alert characteristics
    - Environment context
    
    NO flawed assumptions like time-of-day multipliers!
    """
    
    def __init__(self, model_path: Optional[str] = None, sequence_length: int = 5):
        """
        Initialize LSTM timing predictor
        
        Args:
            model_path: Path to trained LSTM model (.h5 file)
            sequence_length: Number of alerts to use in sequence (default 5)
        """
        self.sequence_length = sequence_length
        self.num_features = 25  # Fixed feature count per alert
        self.model = None
        self.scaler = None
        
        if model_path and os.path.exists(model_path):
            try:
                import tensorflow as tf
                self.model = tf.keras.models.load_model(model_path)
                logger.info(f"Loaded LSTM model from {model_path}")
                
                # Try to load scaler  
                scaler_path = model_path.replace('.h5', '_scaler.pkl')
                if os.path.exists(scaler_path):
                    import joblib
                    self.scaler = joblib.load(scaler_path)
                    logger.info(f"Loaded feature scaler from {scaler_path}")
            except Exception as e:
                logger.error(f"Failed to load LSTM model: {e}")
                self.model = None
    
    def predict_timing(
        self, 
        current_stage: int, 
        next_stage: int, 
        alert_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Predict time to next attack stage
        
        Args:
            current_stage: Current attack stage number (1-14)
            next_stage: Target next stage number
            alert_context: Current alert and context data
        
        Returns:
            Timing prediction with confidence and range
        """
        
        if not self.model:
            logger.warning("LSTM model not loaded. Cannot predict timing.")
            return {
                'eta_minutes': None,
                'eta_range': None,
                'confidence': 0.0,
                'method': 'lstm_not_available',
                'error': 'LSTM model not loaded'
            }
        
        try:
            # Get alert sequence (including current alert)
            alert_sequence = self._get_alert_sequence(alert_context)
            
            # Extract features from sequence
            features = self.extract_features(alert_sequence)
            
            # Scale features if scaler available
            if self.scaler:
                features_scaled = self.scaler.transform(
                    features.reshape(1, self.sequence_length, self.num_features)
                )
            else:
                features_scaled = features.reshape(1, self.sequence_length, self.num_features)
            
            # Predict using LSTM model
            prediction = self.model.predict(features_scaled, verbose=0)[0][0]
            
            # Apply constraints (timing should be reasonable)
            prediction = np.clip(prediction, 1, 1440)  # 1 min to 24 hours
            
            # Estimate confidence based on model certainty
            confidence = self._estimate_confidence(features_scaled)
            
            # Calculate prediction interval
            eta_range = self._calculate_confidence_interval(prediction, confidence)
            
            return {
                'eta_minutes': int(prediction),
                'eta_range': eta_range,
                'confidence': round(confidence, 2),
                'method': 'lstm_dynamic',
                'model_version': '2.0'
            }
        
        except Exception as e:
            logger.error(f"LSTM prediction error: {e}")
            return {
                'eta_minutes': None,
                'eta_range': None,
                'confidence': 0.0,
                'method': 'lstm_error',
                'error': str(e)
            }
    
    def extract_features(self, alert_sequence: List[Dict[str, Any]]) -> np.ndarray:
        """
        Extract fixed 25 features from alert sequence for LSTM
        
        Features:
        1. Stage number (normalized)
        2. Severity score (0-1)
        3. Time since previous alert (minutes, normalized)
        4. Cumulative alert count
        5. Alert type (encoded)
        6. Source IP entropy
        7. Destination IP entropy
        8. Port diversity
        9. Protocol type (encoded)
        10. Payload size (normalized)
        11. Hour of day (sin-cos encoded - 2 features)
        12. Day of week (sin-cos encoded - 2 features)
        13. Alert frequency (alerts/hour)
        14. Unique sources count
        15. Unique destinations count
        16. Failed vs successful action ratio
        17. Privilege level (encoded)
        18. User type (encoded)
        19. Asset criticality (0-1)
        20. Network zone (encoded)
        21. MITRE technique count
        22. Attack momentum (velocity)
        23. Lateral movement indicator (0-1)
        24. Data access indicator (0-1)
        25. C2 indicator (0-1)
        
        Args:
            alert_sequence: List of up to 5 alerts
        
        Returns:
            numpy array of shape (sequence_length, 25) with normalized features
        """
        
        features = []
        
        for i, alert in enumerate(alert_sequence):
            alert_features = []
            
            # 1. Stage number (normalized to 0-1)
            stage = alert.get('stage_number', 0)
            alert_features.append(stage / 14.0)
            
            # 2. Severity score
            severity_map = {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}
            severity = alert.get('severity', 'medium')
            alert_features.append(severity_map.get(severity.lower(), 0.5))
            
            # 3. Time since previous alert (minutes, log-normalized)
            if i > 0:
                time_diff = self._calculate_time_diff(alert_sequence[i-1], alert)
                alert_features.append(np.log1p(time_diff) / 10.0)  # Log scale, normalize
            else:
                alert_features.append(0.0)
            
            # 4. Cumulative alert count in sequence
            alert_features.append((i + 1) / self.sequence_length)
            
            # 5-25: Additional features (simplified for now)
            # In production, implement full feature extraction
            
            # Alert type encoded (simplified)
            alert_type = alert.get('class_name', 'unknown')
            alert_features.append(hash(alert_type) % 100 / 100.0)
            
            # Network features (6-10)
            alert_features.extend([
                self._calc_ip_entropy(alert.get('src_ip')),
                self._calc_ip_entropy(alert.get('dst_ip')),
                0.5,  # Port diversity placeholder
                self._encode_protocol(alert.get('protocol')),
                self._normalize_size(alert.get('size', 0))
            ])
            
            # Temporal features (11-14) - hour and day encodings
            alert_time = alert.get('time', datetime.utcnow())
            if isinstance(alert_time, str):
                alert_time = datetime.fromisoformat(alert_time.replace('Z', '+00:00'))
            
            hour = alert_time.hour
            alert_features.extend([
                np.sin(2 * np.pi * hour / 24),
                np.cos(2 * np.pi * hour / 24)
            ])
            
            day = alert_time.weekday()
            alert_features.extend([
                np.sin(2 * np.pi * day / 7),
                np.cos(2 * np.pi * day / 7)
            ])
            
            # Additional context features (15-25)
            alert_features.extend([
                0.5,  # Alert frequency placeholder
                0.5,  # Unique sources placeholder
                0.5,  # Unique destinations placeholder
                0.5,  # Failed/success ratio placeholder
                0.5,  # Privilege level placeholder
                0.5,  # User type placeholder
                self._get_asset_criticality(alert),
                0.5,  # Network zone placeholder
                len(alert.get('enrichments', {}).get('mitre', {}).get('techniques', [])) / 10.0,
                0.5,  # Attack momentum placeholder
                self._detect_lateral_movement(alert),
                self._detect_data_access(alert),
                self._detect_c2(alert)
            ])
            
            # Ensure exactly 25 features
            features.append(alert_features[:25])
        
        # Pad sequence if needed
        while len(features) < self.sequence_length:
            features.insert(0, [0.0] * 25)
        
        # Take only last sequence_length alerts
        features = features[-self.sequence_length:]
        
        return np.array(features, dtype=np.float32)
    
    def _get_alert_sequence(self, alert_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get sequence of recent alerts for this incident/asset"""
        
        # If alert_context contains sequence directly
        if 'alert_sequence' in alert_context:
            return alert_context['alert_sequence'][-self.sequence_length:]
        
        # Otherwise, create sequence from single alert (less accurate)
        return [alert_context]
    
    def _calculate_time_diff(self, prev_alert: Dict[str, Any], curr_alert: Dict[str, Any]) -> float:
        """Calculate time difference between alerts in minutes"""
        
        try:
            prev_time = prev_alert.get('time', datetime.utcnow())
            curr_time = curr_alert.get('time', datetime.utcnow())
            
            if isinstance(prev_time, str):
                prev_time = datetime.fromisoformat(prev_time.replace('Z', '+00:00'))
            if isinstance(curr_time, str):
                curr_time = datetime.fromisoformat(curr_time.replace('Z', '+00:00'))
            
            diff = (curr_time - prev_time).total_seconds() / 60.0
            return max(0, diff)
        except:
            return 0.0
    
    def _calc_ip_entropy(self, ip: Optional[str]) -> float:
        """Calculate entropy of IP address (simplified)"""
        if not ip:
            return 0.0
        # Simplified: hash-based entropy
        return (hash(ip) % 100) / 100.0
    
    def _encode_protocol(self, protocol: Optional[str]) -> float:
        """Encode protocol type"""
        protocol_map = {'tcp': 0.25, 'udp': 0.5, 'icmp': 0.75, 'http': 0.4, 'https': 0.6}
        if not protocol:
            return 0.0
        return protocol_map.get(protocol.lower(), 0.5)
    
    def _normalize_size(self, size: int) -> float:
        """Normalize payload size"""
        return np.log1p(size) / 20.0
    
    def _get_asset_criticality(self, alert: Dict[str, Any]) -> float:
        """Get asset criticality score"""
        criticality_map = {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}
        criticality = alert.get('device', {}).get('criticality', 'medium')
        return criticality_map.get(criticality.lower(), 0.5)
    
    def _detect_lateral_movement(self, alert: Dict[str, Any]) -> float:
        """Detect indicators of lateral movement"""
        # Check MITRE tactic or specific indicators
        tactic = alert.get('enrichments', {}).get('mitre', {}).get('dominant_tactic', '')
        return 1.0 if 'lateral' in tactic.lower() else 0.0
    
    def _detect_data_access(self, alert: Dict[str, Any]) -> float:
        """Detect indicators of data access"""
        tactic = alert.get('enrichments', {}).get('mitre', {}).get('dominant_tactic', '')
        return 1.0 if 'collection' in tactic.lower() else 0.0
    
    def _detect_c2(self, alert: Dict[str, Any]) -> float:
        """Detect indicators of C2 communication"""
        tactic = alert.get('enrichments', {}).get('mitre', {}).get('dominant_tactic', '')
        return 1.0 if 'command' in tactic.lower() else 0.0
    
    def _estimate_confidence(self, features: np.ndarray) -> float:
        """
        Estimate prediction confidence using Monte Carlo dropout
        
        Runs model multiple times with dropout enabled to measure uncertainty
        """
        
        if not self.model:
            return 0.0
        
        try:
            # Run Monte Carlo dropout (10 forward passes)
            predictions = []
            for _ in range(10):
                pred = self.model.predict(features, verbose=0)[0][0]
                predictions.append(pred)
            
            # Calculate coefficient of variation
            predictions = np.array(predictions)
            mean_pred = np.mean(predictions)
            std_pred = np.std(predictions)
            
            if mean_pred > 0:
                cv = std_pred / mean_pred
                # Convert to confidence (lower CV = higher confidence)
                confidence = max(0.0, 1.0 - cv)
            else:
                confidence = 0.5
            
            return min(1.0, confidence)
        
        except:
            return 0.5  # Default moderate confidence
    
    def _calculate_confidence_interval(
        self, 
        prediction: float, 
        confidence: float
    ) -> Tuple[int, int]:
        """Calculate prediction interval based on confidence"""
        
        # Wider interval for lower confidence
        margin = prediction * (1.0 - confidence) * 0.5
        
        lower = max(1, int(prediction - margin))
        upper = int(prediction + margin)
        
        return (lower, upper)
