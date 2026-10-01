"""
Anomaly Detector - Model 1
Capability 3: Behavioral Anomaly Detection

Uses Isolation Forest (unsupervised) to detect unusual security alerts
No labeled data required - trains on 30 days of normal alerts
"""

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import pickle
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import hashlib

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for security alerts
    
    Features:
    - 48 total features extracted from each alert
    - Unsupervised learning (no labels needed)
    - Trains on 30 days of historical alerts
    - Returns anomaly score 0.0-1.0 (higher = more anomalous)
    """
    
    def __init__(self):
        """Initialize Isolation Forest model"""
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.01,  # Expect 1% anomalies
            max_samples=256,
            random_state=42,
            n_jobs=-1,
            bootstrap=False
        )
        self.scaler = StandardScaler()
        self.feature_names = self._get_feature_names()
        self.trained = False
        
    def _get_feature_names(self) -> List[str]:
        """Get names of all 48 features"""
        return [
            # Temporal (6)
            "hour_of_day",
            "day_of_week",
            "is_weekend",
            "is_business_hours",
            "time_since_last_alert",
            "alert_frequency_last_hour",
            
            # Rule-based (8)
            "rule_level",
            "num_rule_groups",
            "num_mitre_ids",
            "is_auth_related",
            "is_privilege_related",
            "is_pci_related",
            "is_nist_related",
            "has_cve",
            
            # Network (8)
            "src_ip_numeric",
            "src_port_normalized",
            "dst_ip_numeric",
            "dst_port_normalized",
            "protocol_type",
            "bytes_sent_normalized",
            "bytes_received_normalized",
            "session_duration",
            
            # User/Asset (8)
            "user_hash",
            "asset_hash",
            "asset_criticality",
            "user_privilege_level",
            "uses_sudo",
            "is_external_ip",
            "geo_risk_score",
            "is_known_good_ip",
            
            # Context (10)
            "similar_alerts_last_hour",
            "similar_alerts_last_day",
            "correlation_group_size",
            "is_first_time_seen",
            "historical_fp_rate",
            "vt_reputation_score",
            "threat_intel_match",
            "has_sensitive_data",
            "in_maintenance_window",
            "compliance_violation",
            
            # Behavioral (8)
            "user_deviation_score",
            "asset_deviation_score",
            "unusual_time",
            "unusual_location",
            "unusual_action",
            "unusual_target",
            "unusual_volume",
            "pattern_break_score"
        ]
    
    def train(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train on 30 days of normal alerts
        
        Args:
            alerts: List of alert dictionaries (10,000-50,000 alerts)
            
        Returns:
            Training statistics
        """
        logger.info(f"Training on {len(alerts)} alerts...")
        
        if len(alerts) < 1000:
            logger.warning(f"Only {len(alerts)} alerts provided. Recommend 10,000+ for good performance.")
        
        # Extract features
        X = self.extract_features(alerts)
        logger.info(f"Extracted features shape: {X.shape}")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model.fit(X_scaled)
        
        self.trained = True
        logger.info("✅ Anomaly Detector trained successfully")
        
        # Calculate training stats
        train_scores = self.model.score_samples(X_scaled)
        
        # Use model's own prediction to count anomalies (based on contamination)
        predictions = self.model.predict(X_scaled)  # -1 for anomaly, 1 for normal
        anomaly_count = np.sum(predictions == -1)
        
        # Get the actual threshold used by the model
        threshold_score = np.percentile(train_scores, self.model.contamination * 100)
        
        return {
            "num_alerts_trained": len(alerts),
            "num_features": X.shape[1],
            "estimated_anomalies": int(anomaly_count),
            "anomaly_rate": float(anomaly_count / len(alerts)),
            "model_contamination": self.model.contamination,
            "decision_threshold": float(threshold_score)
        }
    
    def predict(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict anomaly score for single alert
        
        Args:
            alert: Alert dictionary
            
        Returns:
            {
                "anomaly_score": 0.0-1.0,
                "is_anomaly": bool,
                "confidence": float,
                "raw_score": float
            }
        """
        if not self.trained:
            raise ValueError("Model not trained yet! Call train() first.")
        
        X = self.extract_features([alert])
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score (-1 to +1, lower = more anomalous)
        score = self.model.score_samples(X_scaled)[0]
        
        # Get model's binary prediction
        prediction = self.model.predict(X_scaled)[0]  # -1 or 1
        
        # Convert to probability (0-1, higher = more anomalous)
        anomaly_prob = 1 / (1 + np.exp(score))
        
        # Confidence: how far from 0.5 (uncertainty)
        # Ranges from 0 (unsure) to 1 (very confident)
        confidence = abs(anomaly_prob - 0.5) * 2
        
        return {
            "anomaly_score": float(anomaly_prob),
            "is_anomaly": prediction == -1,  # Use model's decision
            "confidence": float(confidence),
            "raw_score": float(score)
        }
    
    def extract_features(self, alerts: List[Dict[str, Any]]) -> np.ndarray:
        """
        Extract 48 features from alerts
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            Feature matrix (n_alerts, 48)
        """
        features = []
        
        for alert in alerts:
            f = self._extract_single_alert_features(alert)
            features.append(f)
        
        return np.array(features)
    
    def _extract_single_alert_features(self, alert: Dict[str, Any]) -> List[float]:
        """Extract 48 features from a single alert (Wazuh format)"""
        
        # Helper to get nested or flat keys
        def get_val(key_path, default=None):
            if key_path in alert:
                return alert[key_path]
            parts = key_path.split('.')
            val = alert
            for p in parts:
                if isinstance(val, dict) and p in val:
                    val = val[p]
                else:
                    return default
            return val

        # Get timestamp
        timestamp = get_val('timestamp', datetime.utcnow())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        elif isinstance(timestamp, int):
            timestamp = datetime.fromtimestamp(timestamp / 1000)
        
        # TEMPORAL FEATURES (6)
        enrichment = get_val('enrichment', {}) or {}
        
        temporal = [
            float(timestamp.hour),  # 0-23
            float(timestamp.weekday()),  # 0-6
            float(timestamp.weekday() >= 5),  # is_weekend
            float(9 <= timestamp.hour <= 17),  # is_business_hours
            float(get_val('enrichment.time_since_last', enrichment.get('time_since_last', 0.0))),  # time_since_last_alert
            float(get_val('enrichment.freq_last_hour', enrichment.get('freq_last_hour', 0.0)))   # alert_frequency_last_hour
        ]
        
        # RULE-BASED FEATURES (8)
        severity = get_val('rule.level', 5)
        
        # Handle mitre_ids whether it's a list or single value
        mitre_val = get_val('rule.mitre.id', [])
        mitre_ids = mitre_val if isinstance(mitre_val, list) else [mitre_val]
        
        groups_val = get_val('rule.groups', [])
        groups = groups_val if isinstance(groups_val, list) else [groups_val]
        
        finding_desc = str(get_val('rule.description', '')).lower()
        has_cve = get_val('enrichment.has_cve', get_val('vulnerability', 0.0))
        if isinstance(has_cve, dict):
            has_cve = 1.0
        
        rule_based = [
            float(severity),
            float(len(groups)),
            float(len(mitre_ids)),
            float('auth' in finding_desc or 'authentication' in finding_desc or 'login' in finding_desc),
            float('privilege' in finding_desc or 'elevat' in finding_desc or 'root' in finding_desc),
            float('pci' in finding_desc or 'pci_dss' in groups),
            float('nist' in finding_desc or 'nist_800_53' in groups),
            float(has_cve)
        ]
        
        # NETWORK FEATURES (8)
        src_ip = get_val('data.srcip', get_val('srcip', '0.0.0.0'))
        dst_ip = get_val('data.dstip', get_val('dstip', '0.0.0.0'))
        src_port = get_val('data.srcport', 0)
        dst_port = get_val('data.dstport', 0)
        protocol = get_val('data.protocol', 'tcp')
        
        network = [
            float(self._ip_to_numeric(src_ip)),
            float(src_port) / 65535.0 if src_port else 0.0,
            float(self._ip_to_numeric(dst_ip)),
            float(dst_port) / 65535.0 if dst_port else 0.0,
            float(self._protocol_to_numeric(protocol)),
            float(get_val('data.bytes_sent', 0)) / 1000000.0,
            float(get_val('data.bytes_received', 0)) / 1000000.0,
            float(get_val('data.duration', 0)) / 60.0
        ]
        
        # USER/ASSET FEATURES (8)
        user = get_val('data.dstuser', get_val('username', 'unknown'))
        device_uid = get_val('agent.id', get_val('agent.name', 'unknown'))
        
        is_privileged = (str(user).lower() in ['root', 'admin', 'administrator']) or ('sudo' in finding_desc)
        
        user_asset = [
            float(self._string_to_hash(user)),
            float(self._string_to_hash(device_uid)),
            float(get_val('enrichment.asset_crit', enrichment.get('asset_crit', 0.5))),
            float(1.0 if is_privileged else 0.3),  # Privilege level
            float(is_privileged),  # Uses elevated privileges
            float(self._is_external_ip(src_ip)),
            float(get_val('enrichment.risk_score', enrichment.get('risk_score', 50.0)) / 100.0),
            float(self._is_known_good_ip(src_ip))
        ]
        
        # CONTEXT FEATURES (10)
        vt_score = 0.5
        threat_match = False
        
        context = [
            float(get_val('enrichment.sim_1h', enrichment.get('sim_1h', 0.0))),
            float(get_val('enrichment.sim_1d', enrichment.get('sim_1d', 0.0))),
            float(1.0),  # correlation_group_size placeholder for single alert
            float(get_val('enrichment.first_seen', enrichment.get('first_seen', 0.0))),
            float(get_val('enrichment.hist_fp_rate', enrichment.get('hist_fp_rate', 0.0))),
            float(vt_score),
            float(threat_match),
            float(get_val('enrichment.has_sensitive', enrichment.get('has_sensitive', 0.0))),
            0.0,  # in_maintenance_window (REMOVED logic as per user: 0.0 placeholder to keep 48 size)
            0.0   # compliance_violation
        ]
        
        # BEHAVIORAL FEATURES
        behavioral = [
            float(get_val('enrichment.user_dev', enrichment.get('user_dev', 0.0))),
            float(get_val('enrichment.asset_dev', enrichment.get('asset_dev', 0.0))),
            float(get_val('enrichment.unusual_time', enrichment.get('unusual_time', 0.0))),
            float(get_val('enrichment.unusual_loc', enrichment.get('unusual_loc', 0.0))),
            float(get_val('enrichment.unusual_action', enrichment.get('unusual_action', 0.0))),
            float(get_val('enrichment.unusual_tgt', enrichment.get('unusual_tgt', 0.0))),
            float(get_val('enrichment.unusual_vol', enrichment.get('unusual_vol', 0.0))),
            0.0   # pattern_break_score (REMOVED logic as per user: 0.0 placeholder to keep 48 size)
        ]
        
        # Combine all features
        all_features = temporal + rule_based + network + user_asset + context + behavioral
        
        assert len(all_features) == 48, f"Expected 48 features, got {len(all_features)}"
        
        return all_features
    
    def _ip_to_numeric(self, ip: str) -> int:
        """Convert IP address to numeric value"""
        try:
            parts = ip.split('.')
            return int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3])
        except:
            return 0
    
    def _protocol_to_numeric(self, protocol: str) -> int:
        """Convert protocol to numeric"""
        protocol_map = {'tcp': 1, 'udp': 2, 'icmp': 3, 'http': 4, 'https': 5}
        return protocol_map.get(str(protocol).lower(), 0)
    
    def _string_to_hash(self, s: str) -> int:
        """Convert string to numeric hash (0-1)"""
        try:
            h = hashlib.md5(str(s).encode()).hexdigest()
            return int(h[:8], 16) / 0xFFFFFFFF
        except:
            return 0.5
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (not private)"""
        try:
            parts = [int(x) for x in ip.split('.')]
            # Private IP ranges
            if parts[0] == 10:
                return False
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return False
            if parts[0] == 192 and parts[1] == 168:
                return False
            return True
        except:
            return False
    
    def _is_known_good_ip(self, ip: str) -> bool:
        """Check if IP is in known good list (placeholder)"""
        # TODO: Implement actual known good IP list
        return False
    
    def save(self, path: str = "models/anomaly_detector.pkl") -> None:
        """Save trained model"""
        if not self.trained:
            raise ValueError("Model not trained yet!")
        
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'trained': self.trained
            }, f)
        logger.info(f"✅ Model saved to {path}")
    
    def load(self, path: str = "models/anomaly_detector.pkl") -> None:
        """Load trained model"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.scaler = data['scaler']
            self.feature_names = data['feature_names']
            self.trained = data['trained']
        logger.info(f"✅ Model loaded from {path}")


# Module-level singleton for easy import
detector = AnomalyDetector()
