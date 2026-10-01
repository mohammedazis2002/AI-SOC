# SOAR Platform: ML Models Implementation Roadmap
## Week-by-Week Execution Plan with Exact Models & Order

---

# EXECUTIVE SUMMARY

## **Timeline Overview:**
- **Weeks 1-3:** Foundation + Data Collection (NO ML yet)
- **Week 4:** First ML Models (2 models)
- **Week 5:** Behavioral ML (3 models)
- **Week 6:** Advanced ML (3 models)
- **Week 7-8:** Integration + Fine-tuning
- **Week 9:** ML Training with Collected Feedback (CRITICAL)
- **Week 10-12:** Testing + Deployment

## **Total ML Models: 8**
## **Implementation Order: Strategic Sequencing**

---

# PHASE 1: FOUNDATION (Weeks 1-3)
## **NO ML MODELS YET - Data Collection Period**

### **Week 1-3 Focus:**
```
✅ Infrastructure setup (Docker, MongoDB, Redis)
✅ Ingestion pipeline (FastAPI)
✅ ULF schema implementation
✅ Wazuh integration
✅ Dashboard skeleton (React)
✅ Feedback UI (CRITICAL for Week 9)
```

### **CRITICAL: Feedback Collection Starts Week 1**
```python
# Simple feedback UI deployed Week 1
class FeedbackCollector:
    """
    Analysts manually label alerts:
    - True Positive / False Positive
    - Correct severity? Yes/No
    - Root cause (if known)
    - Action taken
    - Outcome (attack stopped / false alarm / attack succeeded)
    """
    
# Goal by Week 9: 500+ labeled samples
# Collection rate needed: ~60 labels per week
```

### **Why No ML Yet?**
1. ⚠️ Need data to train models
2. ⚠️ Need infrastructure first
3. ⚠️ Need feedback pipeline operational
4. ⚠️ Bootstrap approach: collect labels for supervised models

---

---

# PHASE 2: FIRST ML MODELS (Week 4)
## **2 Models Deployed**

---

## **MODEL 1: Anomaly Detector (Isolation Forest)**
### **Deployed: Week 4 - Monday-Tuesday**

### **Why First?**
✅ **Unsupervised** - Doesn't need labeled data!
✅ **Fast to train** - 30 days of normal alerts is enough
✅ **Immediate value** - Provides anomaly scores for all other components
✅ **Foundation** - Other models will use these scores

### **Implementation Details:**

**Algorithm:** Isolation Forest (sklearn)

**Training Data:**
```python
# Collect 30 days of "normal" alerts from Wazuh
# No labels needed - just raw alerts

training_data = {
    "source": "Wazuh alerts (last 30 days)",
    "volume": "10,000-50,000 alerts",
    "labeling": "NONE - unsupervised learning",
    "features": 48,
    "preparation_time": "2 hours to extract features"
}
```

**Features (48 total):**
```python
features = [
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
    "user_deviation_score",  # Will be 0 until UBA in Week 5
    "asset_deviation_score",
    "unusual_time",
    "unusual_location",
    "unusual_action",
    "unusual_target",
    "unusual_volume",
    "pattern_break_score"
]
```

**Code Implementation:**
```python
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import pickle

class AnomalyDetector:
    """
    Capability 3: Behavioral Anomaly Detection
    """
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.01,  # Expect 1% anomalies
            max_samples=256,
            random_state=42,
            n_jobs=-1,
            bootstrap=False
        )
        self.scaler = StandardScaler()
        self.feature_names = None
        
    def train(self, alerts):
        """
        Train on 30 days of normal alerts
        
        Args:
            alerts: List of alert dictionaries
        """
        print(f"Training on {len(alerts)} alerts...")
        
        # Extract features
        X = self.extract_features(alerts)
        print(f"Extracted features shape: {X.shape}")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model.fit(X_scaled)
        
        print("✅ Anomaly Detector trained successfully")
        
    def predict(self, alert):
        """
        Predict anomaly score for single alert
        
        Returns:
            {
                "anomaly_score": 0.0-1.0,
                "is_anomaly": bool,
                "confidence": float
            }
        """
        X = self.extract_features([alert])
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score (-1 to +1)
        score = self.model.score_samples(X_scaled)[0]
        
        # Convert to probability (0-1, higher = more anomalous)
        anomaly_prob = 1 / (1 + np.exp(score))
        
        return {
            "anomaly_score": float(anomaly_prob),
            "is_anomaly": anomaly_prob > 0.75,
            "confidence": abs(score),
            "raw_score": float(score)
        }
    
    def save(self, path="models/anomaly_detector.pkl"):
        """Save trained model"""
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names
            }, f)
        print(f"✅ Model saved to {path}")
    
    def load(self, path="models/anomaly_detector.pkl"):
        """Load trained model"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.scaler = data['scaler']
            self.feature_names = data['feature_names']
        print(f"✅ Model loaded from {path}")

# Week 4 Training Script
if __name__ == "__main__":
    # Load 30 days of alerts
    alerts = load_alerts_from_mongodb(days=30)
    print(f"Loaded {len(alerts)} alerts")
    
    # Train detector
    detector = AnomalyDetector()
    detector.train(alerts)
    
    # Test on sample
    test_alert = alerts[0]
    result = detector.predict(test_alert)
    print(f"Test result: {result}")
    
    # Save model
    detector.save()
```

**Deployment:**
```yaml
# Week 4 - Tuesday afternoon
Service: anomaly-detector-service
Port: 5001
Endpoints:
  - POST /predict
  - GET /health
  - GET /metrics

Integration:
  - Alert ingestion pipeline calls this service for every alert
  - Latency target: <10ms per alert
  - Throughput: 100+ alerts/second
```

**Success Metrics:**
```
Week 4 End:
✅ Model trained on 30+ days data
✅ Anomaly scores available for all new alerts
✅ <10ms latency
✅ Integrated into pipeline
```

---

## **MODEL 5: Time Series Forecaster (Prophet)**
### **Deployed: Week 4 - Wednesday-Thursday**

### **Why Second?**
✅ **Simple training** - Just needs historical alert counts
✅ **No labels needed** - Time series only
✅ **High impact** - Predicts attack windows
✅ **Foundation for Agent 5** - Forecasting capability

### **Implementation Details:**

**Algorithm:** Prophet (Facebook)

**Purpose:** Capability 8 (Predictive Attack Forecasting) - Part 1

**Training Data:**
```python
training_data = {
    "source": "Historical alert counts",
    "timeframe": "Last 6 months (minimum)",
    "granularity": "Hourly aggregates",
    "volume": "~4,380 data points (6 months × 30 days × 24 hours)",
    "labeling": "NONE - time series only",
    "features": ["timestamp", "alert_count"]
}
```

**Code Implementation:**
```python
from prophet import Prophet
import pandas as pd
from datetime import datetime, timedelta

class AttackWindowForecaster:
    """
    Capability 8: Predictive Attack Forecasting (Time Series)
    Predicts when attack spikes will occur
    """
    def __init__(self):
        self.model = Prophet(
            daily_seasonality=True,
            weekly_seasonality=True,
            yearly_seasonality=False,  # MVP doesn't need this
            changepoint_prior_scale=0.05,
            interval_width=0.8
        )
        self.trained = False
        
    def train(self, alert_counts):
        """
        Train on historical hourly alert counts
        
        Args:
            alert_counts: DataFrame with columns ['ds', 'y']
                         ds = timestamp
                         y = alert count
        """
        print(f"Training on {len(alert_counts)} hourly data points...")
        
        # Prophet requires specific column names
        df = alert_counts.rename(columns={
            'timestamp': 'ds',
            'count': 'y'
        })
        
        # Train
        self.model.fit(df)
        self.trained = True
        
        print("✅ Attack Window Forecaster trained successfully")
        
    def forecast(self, hours_ahead=48):
        """
        Predict next 24-48 hours
        
        Returns:
            List of predictions with high-risk windows highlighted
        """
        if not self.trained:
            raise ValueError("Model not trained yet!")
        
        # Create future dataframe
        future = self.model.make_future_dataframe(
            periods=hours_ahead,
            freq='H'
        )
        
        # Forecast
        forecast = self.model.predict(future)
        
        # Identify high-risk windows (90th percentile)
        threshold = forecast['yhat'].quantile(0.90)
        
        # Get only future predictions
        future_forecast = forecast.tail(hours_ahead)
        
        # Extract high-risk windows
        high_risk_windows = []
        for _, row in future_forecast.iterrows():
            if row['yhat'] > threshold:
                high_risk_windows.append({
                    "timestamp": row['ds'].isoformat(),
                    "predicted_alerts": int(row['yhat']),
                    "confidence_lower": int(row['yhat_lower']),
                    "confidence_upper": int(row['yhat_upper']),
                    "risk_level": "high"
                })
        
        return {
            "forecast_horizon_hours": hours_ahead,
            "high_risk_windows": high_risk_windows,
            "average_predicted": int(future_forecast['yhat'].mean()),
            "peak_predicted": int(future_forecast['yhat'].max())
        }

# Week 4 Training Script
if __name__ == "__main__":
    # Load 6 months of hourly alert counts
    df = load_hourly_alert_counts(months=6)
    print(f"Loaded {len(df)} hourly records")
    
    # Train forecaster
    forecaster = AttackWindowForecaster()
    forecaster.train(df)
    
    # Test forecast
    prediction = forecaster.forecast(hours_ahead=24)
    print(f"Next 24 hours forecast: {prediction}")
    
    # Save model
    import pickle
    with open('models/prophet_forecaster.pkl', 'wb') as f:
        pickle.dump(forecaster, f)
```

**Deployment:**
```yaml
# Week 4 - Thursday afternoon
Service: attack-forecaster-service
Port: 5002
Schedule: Run every 6 hours

Endpoints:
  - GET /forecast?hours=24
  - GET /high_risk_windows
  - GET /metrics

Integration:
  - Cron job runs every 6 hours
  - Results stored in MongoDB
  - Dashboard displays predictions
  - SOC team gets email if high-risk window predicted
```

**Success Metrics:**
```
Week 4 End:
✅ Model trained on 6+ months data
✅ Predicts next 24-48 hours
✅ Identifies high-risk windows
✅ Runs every 6 hours automatically
```

---

## **Week 4 Summary:**

```
✅ 2 ML Models Operational:
   1. Isolation Forest (Anomaly Detection)
   2. Prophet (Time Series Forecasting)

✅ Capabilities Enabled:
   - Capability 3: Behavioral Anomaly Detection (partial)
   - Capability 8: Predictive Attack Forecasting (partial)

✅ Data Pipeline:
   Every alert → Anomaly Detector → Anomaly Score
   Every 6 hours → Forecaster → Attack Window Predictions

✅ Feedback Collection:
   Week 1-4: ~240 labeled alerts collected (target: 500 by Week 9)
```

---

---

# PHASE 3: BEHAVIORAL ML (Week 5)
## **3 More Models Deployed**

---

## **MODEL 4: Attack Chain Detector (Graph Clustering)**
### **Deployed: Week 5 - Monday-Tuesday**

### **Why Third?**
✅ **Uses Model 1 scores** - Builds on anomaly detection
✅ **Rule-based + ML hybrid** - Simpler than pure ML
✅ **High impact** - Cross-device correlation
✅ **Enables Agent 1** - Alert Analysis needs this

### **Implementation Details:**

**Algorithm:** DBSCAN + Graph Clustering (networkx + sklearn)

**Purpose:** Capability 1 (Cross-Device Attack Chain Correlation)

**Training Data:**
```python
# Minimal training - mostly rule-based
training_data = {
    "source": "Historical attack chains (if available)",
    "volume": "100-500 known attack chains (optional)",
    "labeling": "Attack chain labels (optional)",
    "approach": "Primarily rule-based with ML scoring"
}
```

**Code Implementation:**
```python
from sklearn.cluster import DBSCAN
import networkx as nx
import numpy as np
from datetime import timedelta

class AttackChainDetector:
    """
    Capability 1: Cross-Device Attack Chain Correlation
    Groups related alerts into attack chains
    """
    def __init__(self):
        self.dbscan = DBSCAN(
            eps=0.3,
            min_samples=2,
            metric='euclidean'
        )
        self.time_window_minutes = 60
        
    def detect_chains(self, alerts):
        """
        Find attack chains in alert stream
        
        Args:
            alerts: List of recent alerts (last hour)
            
        Returns:
            List of detected attack chains
        """
        if len(alerts) < 2:
            return []
        
        # Build alert graph
        G = self._build_graph(alerts)
        
        # Find connected components (potential chains)
        chains = list(nx.connected_components(G))
        
        # Score each chain
        scored_chains = []
        for chain in chains:
            if len(chain) < 2:
                continue  # Single alert, not a chain
            
            score = self._score_chain(G, chain, alerts)
            
            if score > 0.7:  # Confidence threshold
                chain_info = self._analyze_chain(G, chain, alerts)
                scored_chains.append(chain_info)
        
        return scored_chains
    
    def _build_graph(self, alerts):
        """
        Build graph of related alerts
        """
        G = nx.Graph()
        
        # Add all alerts as nodes
        for alert in alerts:
            G.add_node(alert['alert_id'], data=alert)
        
        # Connect related alerts
        for i, a1 in enumerate(alerts):
            for a2 in alerts[i+1:]:
                weight = self._calculate_similarity(a1, a2)
                
                if weight > 0.3:  # Similarity threshold
                    G.add_edge(
                        a1['alert_id'],
                        a2['alert_id'],
                        weight=weight
                    )
        
        return G
    
    def _calculate_similarity(self, alert1, alert2):
        """
        Calculate how related two alerts are
        """
        weight = 0.0
        
        # Same source IP? +0.5
        if alert1.get('srcip') == alert2.get('srcip'):
            weight += 0.5
        
        # Same destination IP? +0.4
        if alert1.get('dstip') == alert2.get('dstip'):
            weight += 0.4
        
        # Same user? +0.6
        if alert1.get('user') == alert2.get('user'):
            weight += 0.6
        
        # Same host? +0.3
        if alert1.get('agent_id') == alert2.get('agent_id'):
            weight += 0.3
        
        # Within time window? (temporal proximity)
        time_diff = abs(
            (alert2['timestamp'] - alert1['timestamp']).total_seconds() / 60
        )
        if time_diff <= self.time_window_minutes:
            time_factor = 1 - (time_diff / self.time_window_minutes)
            weight *= time_factor
        else:
            weight = 0  # Too far apart in time
        
        # MITRE technique overlap? +0.4
        mitre1 = set(alert1.get('mitre_ids', []))
        mitre2 = set(alert2.get('mitre_ids', []))
        if mitre1 and mitre2:
            overlap = len(mitre1 & mitre2) / len(mitre1 | mitre2)
            weight += 0.4 * overlap
        
        return min(weight, 1.0)  # Cap at 1.0
    
    def _score_chain(self, G, chain_nodes, alerts):
        """
        Calculate confidence that this is a real attack chain
        """
        alerts_in_chain = [
            a for a in alerts if a['alert_id'] in chain_nodes
        ]
        
        # Factor 1: Temporal proximity (0-0.3)
        timestamps = [a['timestamp'] for a in alerts_in_chain]
        time_span = (max(timestamps) - min(timestamps)).total_seconds() / 60
        temporal_score = 0.3 if time_span < 60 else 0.15
        
        # Factor 2: Common attacker indicators (0-0.3)
        unique_ips = len(set(a.get('srcip') for a in alerts_in_chain))
        ip_score = 0.3 if unique_ips <= 2 else 0.1
        
        # Factor 3: Attack progression (0-0.2)
        has_progression = self._check_attack_progression(alerts_in_chain)
        progression_score = 0.2 if has_progression else 0.05
        
        # Factor 4: MITRE chain matching (0-0.2)
        mitre_score = self._check_mitre_chain(alerts_in_chain)
        
        # Total score
        total = temporal_score + ip_score + progression_score + mitre_score
        
        return total
    
    def _check_attack_progression(self, alerts):
        """
        Check if alerts show attack progression
        """
        # Sort by time
        sorted_alerts = sorted(alerts, key=lambda x: x['timestamp'])
        
        # Expected progression stages
        stages = [
            'reconnaissance',
            'initial_access',
            'execution',
            'privilege_escalation',
            'lateral_movement',
            'collection',
            'exfiltration'
        ]
        
        # Map MITRE IDs to stages (simplified)
        stage_keywords = {
            'reconnaissance': ['T1046', 'T1595', 'T1590'],
            'initial_access': ['T1190', 'T1133', 'T1078'],
            'execution': ['T1059', 'T1053'],
            'privilege_escalation': ['T1548', 'T1068'],
            'lateral_movement': ['T1021', 'T1563'],
        }
        
        # Check if progression is logical
        detected_stages = []
        for alert in sorted_alerts:
            for stage, keywords in stage_keywords.items():
                if any(k in alert.get('mitre_ids', []) for k in keywords):
                    detected_stages.append(stage)
                    break
        
        # If we see 3+ stages in logical order, likely a progression
        if len(detected_stages) >= 3:
            return True
        
        return False

# Week 5 Deployment
if __name__ == "__main__":
    # Test with recent alerts
    alerts = get_recent_alerts(hours=1)
    
    detector = AttackChainDetector()
    chains = detector.detect_chains(alerts)
    
    print(f"Found {len(chains)} attack chains")
    for chain in chains:
        print(f"Chain: {chain}")
```

**Deployment:**
```yaml
# Week 5 - Tuesday
Service: attack-chain-detector
Port: 5003
Schedule: Run every 5 minutes on recent alerts

Endpoints:
  - POST /detect_chains
  - GET /active_chains
  - GET /metrics

Integration:
  - Background service processes last hour of alerts
  - Groups into correlation_groups
  - Stores in MongoDB with correlation_group_id
  - Alert Analysis Agent uses this grouping
```

---

## **MODEL 2: False Positive Classifier (XGBoost)**
### **Deployed: Week 9 (NOT Week 5!) - After Feedback Collection**

### **Why Week 9?**
⚠️ **Requires labeled data** - Need 500+ analyst labels
⚠️ **Supervised learning** - Can't train without labels
⚠️ **Weeks 1-8 = Data collection period**

### **Week 5 Alternative: Rule-Based FP Detection**

**Code Implementation (Week 5 - Placeholder):**
```python
class FalsePositiveDetector:
    """
    Week 5: Rule-based heuristics
    Week 9: Will be replaced with XGBoost classifier
    
    Capability 2: Context-Aware False Positive Detection
    """
    def __init__(self):
        self.mode = "heuristic"  # Will become "ml" in Week 9
        
    def predict(self, alert, context):
        """
        Week 5: Use heuristics
        Week 9: Use trained XGBoost model
        """
        if self.mode == "heuristic":
            return self._heuristic_prediction(alert, context)
        else:
            return self._ml_prediction(alert, context)
    
    def _heuristic_prediction(self, alert, context):
        """
        Rule-based FP detection (Week 5-8)
        """
        fp_score = 0.0
        reasons = []
        
        # Check 1: Scheduled task?
        if context.get('matches_schedule'):
            fp_score += 0.3
            reasons.append("Matches daily schedule")
        
        # Check 2: Known automation?
        if alert.get('user') in ['backup_service', 'monitoring_agent']:
            fp_score += 0.4
            reasons.append("Known automation account")
        
        # Check 3: Internal IP + low severity?
        if context.get('is_internal_ip') and alert.get('severity') < 5:
            fp_score += 0.2
            reasons.append("Internal low-severity alert")
        
        # Check 4: Historical FP rate for this rule
        historical_fp_rate = context.get('historical_fp_rate', 0)
        if historical_fp_rate > 0.5:
            fp_score += 0.3
            reasons.append(f"Rule has {historical_fp_rate*100}% FP history")
        
        # Check 5: Maintenance window?
        if context.get('in_maintenance_window'):
            fp_score += 0.5
            reasons.append("During scheduled maintenance")
        
        return {
            "fp_probability": min(fp_score, 1.0),
            "is_false_positive": fp_score > 0.7,
            "method": "heuristic",
            "reasons": reasons
        }

# Week 5 Deployment
detector = FalsePositiveDetector()
result = detector.predict(alert, context)
```

**Week 9 Upgrade (XGBoost):**
```python
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

class FalsePositiveClassifier:
    """
    Week 9: ML-based FP detection
    Trained on 500+ analyst-labeled alerts
    """
    def __init__(self):
        self.model = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=3,  # Handle imbalance
            random_state=42
        )
        self.scaler = StandardScaler()
        self.trained = False
        
    def train(self, labeled_alerts):
        """
        Train on analyst feedback (Week 9)
        
        Args:
            labeled_alerts: List of alerts with analyst labels
                           Must have: is_false_positive (True/False)
        """
        print(f"Training on {len(labeled_alerts)} labeled alerts...")
        
        # Extract features (60 features)
        X = self._extract_features(labeled_alerts)
        y = [1 if a['is_false_positive'] else 0 for a in labeled_alerts]
        
        print(f"Class distribution: TP={sum(1 for i in y if i==0)}, FP={sum(y)}")
        
        # Handle class imbalance
        smote = SMOTE(random_state=42)
        X_balanced, y_balanced = smote.fit_resample(X, y)
        
        print(f"After SMOTE: {X_balanced.shape[0]} samples")
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_balanced, y_balanced, test_size=0.2, random_state=42
        )
        
        # Scale
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train
        self.model.fit(
            X_train_scaled,
            y_train,
            eval_set=[(X_test_scaled, y_test)],
            early_stopping_rounds=10,
            verbose=False
        )
        
        # Evaluate
        from sklearn.metrics import classification_report, roc_auc_score
        y_pred = self.model.predict(X_test_scaled)
        y_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        print("\n" + classification_report(y_test, y_pred))
        print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.3f}")
        
        self.trained = True
        print("✅ FP Classifier trained successfully")
        
    def predict(self, alert, context):
        """
        Predict FP probability
        """
        X = self._extract_features_single(alert, context)
        X_scaled = self.scaler.transform([X])
        
        fp_proba = self.model.predict_proba(X_scaled)[0][1]
        
        # Get feature importance for explanation
        feature_importance = self.model.feature_importances_
        top_features = np.argsort(feature_importance)[-5:]
        
        return {
            "fp_probability": float(fp_proba),
            "is_false_positive": fp_proba > 0.85,
            "confidence": max(fp_proba, 1 - fp_proba),
            "method": "xgboost",
            "top_contributing_features": [
                self.feature_names[i] for i in top_features
            ]
        }

# Week 9 Training Script
if __name__ == "__main__":
    # Load collected feedback (500+ samples)
    labeled_alerts = load_feedback_data()
    print(f"Collected {len(labeled_alerts)} labeled alerts")
    
    if len(labeled_alerts) < 500:
        print("⚠️ WARNING: Need 500+ samples for good performance")
    
    # Train classifier
    classifier = FalsePositiveClassifier()
    classifier.train(labeled_alerts)
    
    # Save model
    import pickle
    with open('models/fp_classifier_xgboost.pkl', 'wb') as f:
        pickle.dump(classifier, f)
    
    print("✅ Model saved - ready for deployment")
```

---

## **MODEL 3: Root Cause Classifier (Random Forest)**
### **Deployed: Week 5 - Wednesday-Thursday**

### **Implementation Details:**

**Algorithm:** Multi-Label Random Forest (sklearn)

**Purpose:** Capability 9 (Automated Root Cause Analysis)

**Training Data:**
```python
training_data = {
    "source": "Historical incidents with known root causes",
    "volume": "100-500 incidents (collect Weeks 1-5)",
    "labeling": "Root cause categories",
    "approach": "Multi-label classification"
}

# Root cause categories (9 classes)
root_causes = [
    "phishing_email",
    "unpatched_vulnerability",
    "weak_credentials",
    "misconfiguration",
    "insider_threat",
    "supply_chain_compromise",
    "stolen_credentials",
    "zero_day_exploit",
    "social_engineering"
]
```

**Code Implementation:**
```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
import numpy as np

class RootCauseClassifier:
    """
    Capability 9: Automated Root Cause Analysis
    Identifies likely attack root cause
    """
    def __init__(self):
        base_rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model = MultiOutputClassifier(base_rf)
        
        self.root_causes = [
            "phishing_email",
            "unpatched_vulnerability",
            "weak_credentials",
            "misconfiguration",
            "insider_threat",
            "supply_chain_compromise",
            "stolen_credentials",
            "zero_day_exploit",
            "social_engineering"
        ]
        
        self.trained = False
        
    def train(self, incident_data):
        """
        Train on historical incidents
        
        Args:
            incident_data: List of incidents with root_causes labels
        """
        print(f"Training on {len(incident_data)} incidents...")
        
        # Extract features
        X = self._extract_features(incident_data)
        
        # Multi-hot encoding for labels
        y = np.zeros((len(incident_data), len(self.root_causes)))
        for i, incident in enumerate(incident_data):
            for cause in incident['root_causes']:
                if cause in self.root_causes:
                    idx = self.root_causes.index(cause)
                    y[i, idx] = 1
        
        print(f"Features shape: {X.shape}")
        print(f"Labels shape: {y.shape}")
        
        # Train
        self.model.fit(X, y)
        
        self.trained = True
        print("✅ Root Cause Classifier trained successfully")
        
    def predict(self, alert_chain):
        """
        Predict root cause for attack chain
        
        Args:
            alert_chain: List of related alerts in sequence
            
        Returns:
            Top 3 likely root causes with probabilities
        """
        X = self._extract_features([alert_chain])
        
        # Predict probabilities
        probas = self.model.predict_proba(X)[0]
        
        # Get probability for each root cause
        cause_probas = []
        for i, cause in enumerate(self.root_causes):
            # Average probability across estimators
            avg_proba = np.mean([p[i][1] if len(p[i]) > 1 else 0 
                                for p in probas])
            cause_probas.append((cause, avg_proba))
        
        # Sort by probability
        cause_probas.sort(key=lambda x: x[1], reverse=True)
        
        # Return top 3
        return {
            "primary_root_cause": cause_probas[0][0],
            "confidence": float(cause_probas[0][1]),
            "top_3_causes": [
                {"cause": c, "probability": float(p)}
                for c, p in cause_probas[:3]
            ],
            "all_causes": [
                {"cause": c, "probability": float(p)}
                for c, p in cause_probas
            ]
        }
    
    def _extract_features(self, incidents):
        """
        Extract 20 features from incident/attack chain
        """
        features = []
        
        for incident in incidents:
            # Get first alert (entry point)
            if isinstance(incident, list):
                entry = incident[0]
                chain_length = len(incident)
            else:
                entry = incident
                chain_length = 1
            
            f = [
                # Entry vector features (4)
                1 if entry.get('is_email_based') else 0,
                1 if entry.get('is_web_based') else 0,
                1 if entry.get('is_network_based') else 0,
                1 if entry.get('is_credential_based') else 0,
                
                # Vulnerability indicators (3)
                1 if entry.get('has_cve') else 0,
                1 if entry.get('is_known_exploit') else 0,
                1 if entry.get('target_is_unpatched') else 0,
                
                # Configuration issues (2)
                1 if entry.get('is_config_error') else 0,
                1 if entry.get('is_permission_issue') else 0,
                
                # Insider threat indicators (3)
                1 if entry.get('is_internal_source') else 0,
                1 if entry.get('is_privileged_user') else 0,
                1 if entry.get('is_off_hours') else 0,
                
                # Attack sophistication (5)
                chain_length,
                incident.get('duration_minutes', 0) / 60,  # Normalize to hours
                1 if incident.get('uses_obfuscation') else 0,
                1 if incident.get('uses_encryption') else 0,
                1 if incident.get('multi_stage') else 0,
                
                # Additional context (3)
                1 if entry.get('from_external_ip') else 0,
                entry.get('severity', 0) / 15,  # Normalize
                entry.get('anomaly_score', 0.5)  # From Model 1
            ]
            
            features.append(f)
        
        return np.array(features)

# Week 5 Training
if __name__ == "__main__":
    # Load historical incidents
    incidents = load_historical_incidents()
    print(f"Loaded {len(incidents)} incidents")
    
    # Train classifier
    classifier = RootCauseClassifier()
    classifier.train(incidents)
    
    # Test
    test_chain = incidents[0]['alert_chain']
    result = classifier.predict(test_chain)
    print(f"Prediction: {result}")
    
    # Save
    import pickle
    with open('models/root_cause_classifier.pkl', 'wb') as f:
        pickle.dump(classifier, f)
```

---

## **Week 5 Summary:**

```
✅ 3 More ML Models Operational:
   4. Attack Chain Detector (Graph Clustering)
   2. FP Detector (Heuristic - will upgrade to XGBoost Week 9)
   3. Root Cause Classifier (Random Forest)

✅ Total ML Models: 5 (+ 1 placeholder)

✅ Capabilities Enabled:
   - Capability 1: Cross-Device Correlation ✅
   - Capability 2: FP Detection (heuristic, will upgrade) ⚠️
   - Capability 9: Root Cause Analysis ✅

✅ Feedback Collection:
   Week 1-5: ~300 labeled alerts (target: 500 by Week 9)
```

---

---

# PHASE 4: ADVANCED ML (Week 6)
## **3 Final Models Deployed**

---

## **MODEL 6: Attack Stage Predictor (LSTM)**
### **Deployed: Week 6 - Monday-Tuesday**

### **Implementation Details:**

**Algorithm:** LSTM Neural Network (TensorFlow/Keras)

**Purpose:** Capability 8 (Predictive Attack Forecasting) - Part 2

**Training Data:**
```python
training_data = {
    "source": "Historical attack sequences",
    "volume": "100-500 attack chains with stage labels",
    "labeling": "Each alert labeled with attack stage",
    "features": "48 features per alert × 10 alerts = 480 inputs",
    "sequence_length": 10  # Last 10 alerts predict next stage
}

# Attack stages (7 classes)
stages = [
    "reconnaissance",
    "initial_access",
    "execution",
    "privilege_escalation",
    "lateral_movement",
    "collection",
    "exfiltration"
]
```

**Code Implementation:**
```python
import tensorflow as tf
from tensorflow import keras
import numpy as np

class AttackStagePredictor:
    """
    Capability 8: Predictive Attack Forecasting (Sequence Prediction)
    Predicts next stage in ongoing attack
    """
    def __init__(self):
        self.stages = [
            "reconnaissance",
            "initial_access",
            "execution",
            "privilege_escalation",
            "lateral_movement",
            "collection",
            "exfiltration"
        ]
        
        self.model = None
        self.scaler = StandardScaler()
        self._build_model()
        
    def _build_model(self):
        """
        Build LSTM architecture
        """
        self.model = keras.Sequential([
            # Input: (batch, 10 alerts, 48 features each)
            keras.layers.LSTM(
                128,
                return_sequences=True,
                input_shape=(10, 48)
            ),
            keras.layers.Dropout(0.2),
            
            keras.layers.LSTM(64),
            keras.layers.Dropout(0.2),
            
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dropout(0.1),
            
            # Output: 7 stage probabilities
            keras.layers.Dense(7, activation='softmax')
        ])
        
        self.model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
    def train(self, attack_sequences):
        """
        Train on historical attack chains
        
        Args:
            attack_sequences: List of attack chains
                             Each chain has alerts with 'stage' labels
        """
        X = []
        y = []
        
        print(f"Preparing training data from {len(attack_sequences)} sequences...")
        
        for sequence in attack_sequences:
            if len(sequence) < 11:
                continue  # Need at least 11 alerts (10 input + 1 target)
            
            # Sliding window approach
            for i in range(len(sequence) - 10):
                # Last 10 alerts as input
                window = sequence[i:i+10]
                X_window = [self._extract_features(a) for a in window]
                
                # Next alert's stage as target
                next_alert = sequence[i+10]
                next_stage = next_alert['stage']
                y_stage = self.stages.index(next_stage)
                
                X.append(X_window)
                y.append(y_stage)
        
        X = np.array(X)
        y = keras.utils.to_categorical(y, num_classes=7)
        
        print(f"Training data shape: X={X.shape}, y={y.shape}")
        
        # Train
        history = self.model.fit(
            X, y,
            epochs=50,
            batch_size=32,
            validation_split=0.2,
            callbacks=[
                keras.callbacks.EarlyStopping(
                    patience=5,
                    restore_best_weights=True
                )
            ],
            verbose=1
        )
        
        print("✅ LSTM Stage Predictor trained successfully")
        return history
        
    def predict(self, recent_alerts):
        """
        Predict next attack stage
        
        Args:
            recent_alerts: Last 10 alerts in sequence
            
        Returns:
            Predicted next stage with confidence
        """
        if len(recent_alerts) < 10:
            return {
                "prediction": "insufficient_data",
                "message": "Need at least 10 alerts to predict"
            }
        
        # Extract features from last 10 alerts
        X = [self._extract_features(a) for a in recent_alerts[-10:]]
        X = np.array([X])  # Shape: (1, 10, 48)
        
        # Predict
        probas = self.model.predict(X, verbose=0)[0]
        next_stage_idx = np.argmax(probas)
        confidence = probas[next_stage_idx]
        
        # Infer current stage from recent alerts
        current_stage = self._infer_current_stage(recent_alerts)
        
        return {
            "current_stage": current_stage,
            "predicted_next_stage": self.stages[next_stage_idx],
            "confidence": float(confidence),
            "all_probabilities": {
                stage: float(prob)
                for stage, prob in zip(self.stages, probas)
            },
            "time_to_next_stage": "15-30 minutes (estimated)",
            "recommended_action": self._get_recommended_action(
                self.stages[next_stage_idx]
            )
        }
    
    def _infer_current_stage(self, alerts):
        """
        Infer current stage from MITRE techniques
        """
        # Map MITRE IDs to stages (simplified)
        stage_map = {
            'T1046': 'reconnaissance',
            'T1190': 'initial_access',
            'T1059': 'execution',
            'T1548': 'privilege_escalation',
            'T1021': 'lateral_movement',
            'T1005': 'collection',
            'T1041': 'exfiltration'
        }
        
        # Check most recent alert's MITRE IDs
        for alert in reversed(alerts):
            for mitre_id in alert.get('mitre_ids', []):
                if mitre_id in stage_map:
                    return stage_map[mitre_id]
        
        return "unknown"
    
    def _get_recommended_action(self, predicted_stage):
        """
        Get recommended preemptive action
        """
        actions = {
            "reconnaissance": "Monitor closely, no action needed yet",
            "initial_access": "Strengthen authentication, review logs",
            "execution": "Enable enhanced monitoring, prepare for isolation",
            "privilege_escalation": "Review privileged accounts, enable MFA",
            "lateral_movement": "Block SMB/RDP between servers immediately",
            "collection": "Enable DLP, monitor data access",
            "exfiltration": "Block external transfers, isolate network"
        }
        
        return actions.get(predicted_stage, "Monitor and investigate")

# Week 6 Training
if __name__ == "__main__":
    # Load attack sequences
    sequences = load_attack_sequences()
    print(f"Loaded {len(sequences)} attack sequences")
    
    # Train
    predictor = AttackStagePredictor()
    history = predictor.train(sequences)
    
    # Test
    test_sequence = sequences[0]
    prediction = predictor.predict(test_sequence[-10:])
    print(f"Prediction: {prediction}")
    
    # Save model
    predictor.model.save('models/lstm_stage_predictor.h5')
    print("✅ Model saved")
```

**Deployment:**
```yaml
# Week 6 - Tuesday
Service: stage-predictor-service
Port: 5004

Endpoints:
  - POST /predict_next_stage
  - GET /metrics

Integration:
  - Triggered when attack chain detected (Model 4)
  - Predicts next stage for ongoing attacks
  - Sends preemptive alerts to SOC team
```

---

## **MODEL 7: RL Response Optimizer (PPO)**
### **Deployed: Week 6 - Wednesday-Friday**

### **Implementation Details:**

**Algorithm:** Proximal Policy Optimization (PPO) - stable-baselines3

**Purpose:** Capability 10 (Dynamic Response Optimization)

**Training Data:**
```python
training_data = {
    "source": "Real action outcomes (continuous learning)",
    "volume": "Starts with 0, grows continuously",
    "labeling": "Automatic (rewards based on outcomes)",
    "approach": "Reinforcement Learning"
}

# 10 possible actions
actions = [
    "do_nothing",
    "alert_analyst",
    "increase_monitoring",
    "block_source_ip",
    "isolate_endpoint",
    "quarantine_file",
    "disable_user_account",
    "patch_vulnerability",
    "rotate_credentials",
    "full_incident_response"
]
```

**Code Implementation:**
```python
from stable_baselines3 import PPO
import gym
from gym import spaces
import numpy as np

class SecurityEnv(gym.Env):
    """
    Custom Gym environment for security decision-making
    """
    def __init__(self):
        super().__init__()
        
        # State space: 20 features
        self.observation_space = spaces.Box(
            low=0,
            high=1,
            shape=(20,),
            dtype=np.float32
        )
        
        # Action space: 10 discrete actions
        self.action_space = spaces.Discrete(10)
        
        self.actions = [
            "do_nothing",
            "alert_analyst",
            "increase_monitoring",
            "block_source_ip",
            "isolate_endpoint",
            "quarantine_file",
            "disable_user_account",
            "patch_vulnerability",
            "rotate_credentials",
            "full_incident_response"
        ]
        
        self.current_state = None
        self.outcome = None
        
    def reset(self):
        """Start new episode with random alert"""
        self.current_state = self._generate_random_state()
        return self.current_state
    
    def step(self, action):
        """
        Execute action, get outcome from real system
        """
        # In production, this would execute the real action
        # and wait for the outcome
        outcome = self._simulate_outcome(action)
        
        # Calculate reward
        reward = self._calculate_reward(action, outcome)
        
        # Episode done
        done = True
        
        return self.current_state, reward, done, {}
    
    def _calculate_reward(self, action, outcome):
        """
        Reward function based on outcomes
        """
        if outcome == "attack_stopped":
            if action in [3, 4, 5, 9]:  # Aggressive actions
                return +10
            elif action == 1:  # Alert analyst
                return +5  # Slower but safe
            else:
                return +3
        
        elif outcome == "false_alarm":
            if action in [4, 6, 9]:  # Isolation, disable, full IR
                return -5  # Too aggressive
            elif action in [1, 2]:  # Alert, monitor
                return +2  # Safe choice
            else:
                return 0
        
        elif outcome == "attack_succeeded":
            if action == 0:  # Do nothing
                return -10  # Very bad
            elif action in [1, 2]:  # Alert, monitor
                return -3  # Too passive
            else:
                return -1
        
        return 0

class RLResponseOptimizer:
    """
    Capability 10: Dynamic Response Optimization
    Learns optimal response actions
    """
    def __init__(self):
        self.env = SecurityEnv()
        
        # PPO agent
        self.agent = PPO(
            "MlpPolicy",
            self.env,
            learning_rate=0.0003,
            n_steps=2048,
            batch_size=64,
            n_epochs=10,
            gamma=0.99,
            gae_lambda=0.95,
            clip_range=0.2,
            verbose=1
        )
        
        self.training_started = False
        self.episodes_trained = 0
        
    def train_initial(self, episodes=1000):
        """
        Initial training (Week 6)
        Uses simulated outcomes
        """
        print(f"Initial training for {episodes} episodes...")
        
        self.agent.learn(total_timesteps=episodes * 100)
        
        self.training_started = True
        self.episodes_trained = episodes
        
        print("✅ Initial RL training complete")
        
    def decide_action(self, alert_state):
        """
        Recommend action for current alert
        
        Args:
            alert_state: 20-feature state vector
            
        Returns:
            Recommended action
        """
        action, _ = self.agent.predict(alert_state, deterministic=True)
        
        return {
            "recommended_action": self.env.actions[action],
            "action_index": int(action),
            "confidence": "learning"  # RL doesn't give confidence initially
        }
    
    def update_from_outcome(self, state, action, outcome):
        """
        Continuous learning from real outcomes
        
        This is called after every action is executed
        """
        # Calculate reward
        reward = self.env._calculate_reward(action, outcome)
        
        # Store experience
        # In production, this would use a replay buffer
        
        # Periodic retraining (every 100 experiences)
        if self.episodes_trained % 100 == 0:
            self.agent.learn(total_timesteps=100)
        
        self.episodes_trained += 1
        
        return {
            "reward": reward,
            "total_episodes": self.episodes_trained
        }

# Week 6 Deployment
if __name__ == "__main__":
    # Create optimizer
    optimizer = RLResponseOptimizer()
    
    # Initial training with simulated data
    optimizer.train_initial(episodes=1000)
    
    # Test decision
    test_state = np.random.rand(20)
    decision = optimizer.decide_action(test_state)
    print(f"Test decision: {decision}")
    
    # Save
    optimizer.agent.save("models/ppo_response_optimizer")
    print("✅ RL agent saved")
```

**Deployment:**
```yaml
# Week 6 - Friday
Service: rl-optimizer-service
Port: 5005

Endpoints:
  - POST /recommend_action
  - POST /update_from_outcome
  - GET /training_stats
  - GET /metrics

Integration:
  - Provides action recommendations to Decision Engine
  - Receives outcome feedback for continuous learning
  - Initially conservative (explores carefully)
  - Improves over weeks 7-12 and beyond
```

---

## **MODEL 8: LLM Agent (Llama-3-8B)**
### **Deployed: Week 6 - Throughout Week**

### **Implementation Details:**

**Algorithm:** Llama-3-8B-Instruct (Quantized GGUF)

**Purpose:** Powers Agent 1 (Alert Analysis) & Agent 2 (Threat Hunting)

**Training Data:**
```python
# Pre-trained model - no training needed initially
# Optional fine-tuning in Week 7-8 with collected feedback

model_info = {
    "model": "Llama-3-8B-Instruct",
    "quantization": "Q4_K_M (4-bit)",
    "size": "~4.5 GB (from 16 GB original)",
    "quality": "~95% of full model performance",
    "vram_required": "8-16 GB"
}
```

**Code Implementation:**
```python
from llama_cpp import Llama
import json

class LLMAlertAnalyzer:
    """
    Model 8: LLM for Alert Analysis
    Powers Agent 1 (Alert Analysis) and Agent 2 (Threat Hunting)
    """
    def __init__(self, model_path="models/llama-3-8b-instruct-q4_k_m.gguf"):
        print(f"Loading LLM from {model_path}...")
        
        self.llm = Llama(
            model_path=model_path,
            n_ctx=4096,  # Context window
            n_threads=8,  # CPU threads
            n_gpu_layers=35,  # Offload to GPU
            verbose=False
        )
        
        self.system_prompt = """You are a cybersecurity analyst AI.
Analyze security alerts and provide structured recommendations.
Always output valid JSON with: classification, severity, 
is_false_positive, recommended_action, justification."""
        
        print("✅ LLM loaded successfully")
        
    def analyze_alert(self, alert, ml_scores, enrichment, rag_docs):
        """
        Analyze alert with full context
        
        Args:
            alert: Alert dictionary
            ml_scores: Scores from ML models
            enrichment: Threat intel, asset context
            rag_docs: Retrieved documents from vector DB
            
        Returns:
            Structured analysis with recommendation
        """
        # Build comprehensive prompt
        prompt = self._build_prompt(alert, ml_scores, enrichment, rag_docs)
        
        # Get LLM response
        response = self.llm(
            prompt,
            max_tokens=500,
            temperature=0.1,  # Low temperature for consistency
            top_p=0.9,
            stop=["}\n", "\n\n\n"]
        )
        
        # Extract and parse JSON
        response_text = response['choices'][0]['text']
        
        try:
            # Try to parse as JSON
            analysis = json.loads(response_text)
        except json.JSONDecodeError:
            # Fallback: extract JSON from text
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                analysis = json.loads(response_text[json_start:json_end])
            else:
                # Parsing failed completely
                analysis = {
                    "classification": "Unknown",
                    "severity": "Medium",
                    "is_false_positive": False,
                    "recommended_action": "manual_review",
                    "justification": "LLM response parsing failed"
                }
        
        return analysis
    
    def _build_prompt(self, alert, ml_scores, enrichment, rag_docs):
        """
        Build comprehensive analysis prompt
        """
        prompt = f"""
{self.system_prompt}

ALERT DETAILS:
{json.dumps(alert, indent=2)}

ML ANALYSIS:
- Anomaly Score: {ml_scores.get('anomaly_score', 'N/A')}
- False Positive Probability: {ml_scores.get('fp_probability', 'N/A')}
- Root Cause Prediction: {ml_scores.get('root_cause', 'N/A')}

THREAT INTELLIGENCE:
{json.dumps(enrichment, indent=2)}

RELEVANT KNOWLEDGE:
{rag_docs}

Analyze this alert and respond with JSON:
{{
  "classification": "Brief description of the threat",
  "severity": "Critical/High/Medium/Low/Informational",
  "is_false_positive": true/false,
  "confidence": 0.0-1.0,
  "recommended_action": "action_name",
  "justification": "Detailed reasoning",
  "additional_actions": ["action1", "action2"],
  "urgency": "immediate/high/medium/low"
}}
"""
        
        return prompt

# Week 6 Deployment
if __name__ == "__main__":
    # Load model
    analyzer = LLMAlertAnalyzer()
    
    # Test analysis
    test_alert = {
        "alert_id": "A-123",
        "rule": {"level": 10, "description": "SSH brute force"},
        "data": {"srcip": "185.220.101.45", "failed_attempts": 150}
    }
    
    test_ml_scores = {
        "anomaly_score": 0.87,
        "fp_probability": 0.12,
        "root_cause": "brute_force_attack"
    }
    
    test_enrichment = {
        "ip_reputation": "malicious",
        "asset_criticality": "high"
    }
    
    test_rag = "MITRE T1110: Brute Force attacks..."
    
    result = analyzer.analyze_alert(
        test_alert,
        test_ml_scores,
        test_enrichment,
        test_rag
    )
    
    print(f"Analysis: {json.dumps(result, indent=2)}")
```

**Deployment:**
```yaml
# Week 6 - Throughout week
Service: llm-analyzer-service
Port: 5006

Endpoints:
  - POST /analyze_alert
  - POST /generate_hypothesis  # For threat hunting
  - GET /health
  - GET /metrics

Hardware:
  - GPU: RTX 4090 (24GB) or 2x RTX 3090
  - Model size: ~4.5 GB
  - Inference latency: <3 seconds per alert

Integration:
  - Alert Analysis Agent (Agent 1)
  - Threat Hunting Agent (Agent 2)
  - Called after all ML models provide their scores
```

---

## **Week 6 Summary:**

```
✅ 3 Final ML Models Deployed:
   6. LSTM Attack Stage Predictor
   7. PPO RL Response Optimizer
   8. Llama-3-8B LLM

✅ Total ML Models: 8 (All deployed!)

✅ Capabilities Enabled:
   - Capability 8: Predictive Forecasting (complete) ✅
   - Capability 10: Response Optimization ✅
   - All 5 AI Agents operational ✅

✅ Feedback Collection:
   Week 1-6: ~360 labeled alerts (target: 500 by Week 9)
```

---

---

# PHASE 5: TRAINING & REFINEMENT (Weeks 7-9)

---

## **Week 7-8: Integration + Fine-Tuning**

### **No New Models - Focus on Quality**

**Week 7 Activities:**
```
✅ Integrate all 8 models into unified pipeline
✅ End-to-end testing
✅ Performance optimization
✅ Latency improvements
✅ Continue feedback collection (target: 450+ by end of Week 8)
```

**Week 8 Activities:**
```
✅ Fine-tune LSTM with more data
✅ Retrain Isolation Forest with updated features
✅ Optimize RL agent with real outcomes
✅ Optional: Fine-tune LLM with domain data
✅ Final feedback push (target: 500+ by Week 9)
```

---

## **Week 9: THE BIG TRAINING WEEK** ⚠️

### **Critical: Train Supervised Models with Collected Feedback**

**Why Week 9 is Critical:**
- ✅ 500+ analyst-labeled alerts collected
- ✅ Can now train XGBoost FP Classifier
- ✅ Can improve Root Cause Classifier
- ✅ Can retrain Anomaly Detector with feedback
- ✅ Can fine-tune LLM (optional)

### **Week 9 Training Schedule:**

**Monday: Data Preparation**
```python
# Collect all feedback
feedback_data = load_all_feedback()
print(f"Total feedback collected: {len(feedback_data)}")

# Validate quality
validate_labels(feedback_data)

# Split for training
train_data, val_data, test_data = split_data(feedback_data)
```

**Tuesday-Wednesday: Train XGBoost FP Classifier**
```python
# FINALLY train the supervised FP classifier
from Week_5_Code import FalsePositiveClassifier

classifier = FalsePositiveClassifier()
classifier.train(train_data)

# Replace heuristic version
deploy_to_production(classifier, replaces="heuristic_fp_detector")
```

**Thursday: Retrain Other Models**
```python
# Retrain Isolation Forest with better features
anomaly_detector_v2.train(normal_alerts + feedback_alerts)

# Retrain Root Cause Classifier with more data
root_cause_v2.train(incident_data + feedback_incidents)
```

**Friday: Validation & Deployment**
```python
# Validate all models
validate_all_models()

# A/B testing setup
setup_ab_testing(old_models, new_models)

# Gradual rollout
deploy_gradually(new_models, percentage=20)
```

---

---

# IMPLEMENTATION SUMMARY

---

## **Complete Model Deployment Timeline:**

| Week | Models Deployed | Total | Purpose |
|------|----------------|-------|---------|
| 1-3 | 0 | 0 | Foundation + Feedback Collection |
| 4 | 2 | 2 | Anomaly Detection + Forecasting |
| 5 | 3 | 5 | Behavioral ML + Root Cause |
| 6 | 3 | 8 | Advanced ML + LLM + RL |
| 7-8 | 0 | 8 | Integration + Optimization |
| 9 | 0 (Retrain) | 8 | Train supervised models with feedback |
| 10-12 | 0 | 8 | Testing + Deployment |

---

## **Model-to-Capability Mapping:**

| Capability | ML Models Used | Week Deployed |
|-----------|---------------|---------------|
| 1. Cross-Device Correlation | Model 4 (Graph Clustering) | Week 5 |
| 2. FP Detection | Model 2 (XGBoost) | Week 9 (heuristic Week 5) |
| 3. Anomaly Detection | Model 1 (Isolation Forest) | Week 4 |
| 4. Asset-Risk Severity | No ML (rule-based) | Week 5 |
| 5. Threat Intel Enrichment | No ML (API integration) | Week 4 |
| 6. Temporal Patterns | Model 5 (Prophet) | Week 4 |
| 7. User Behavior Analytics | Model 1 (Isolation Forest) | Week 5 |
| 8. Predictive Forecasting | Model 5 (Prophet) + Model 6 (LSTM) | Week 4 & 6 |
| 9. Root Cause Analysis | Model 3 (Random Forest) | Week 5 |
| 10. Response Optimization | Model 7 (PPO RL) | Week 6 |

---

## **Agent-to-Model Mapping:**

| Agent | Models Used | Week Operational |
|-------|------------|------------------|
| 1. Alert Analysis | 1, 2, 3, 8 | Week 6 (full), Week 9 (optimized) |
| 2. Threat Hunting | 1, 8 | Week 6 |
| 3. Verification | 1, 2 | Week 6 (full), Week 9 (optimized) |
| 4. RL Optimizer | 7 | Week 6 |
| 5. Forecasting | 5, 6 | Week 6 |

---

## **Data Requirements by Week:**

| Week | Data Needed | Purpose |
|------|------------|---------|
| 1-3 | 30 days normal alerts | Train Isolation Forest (Week 4) |
| 1-3 | 6 months alert counts | Train Prophet (Week 4) |
| 1-8 | 500+ labeled alerts | Train XGBoost FP (Week 9) ⚠️ CRITICAL |
| 1-5 | 100+ historical incidents | Train Root Cause (Week 5) |
| 1-5 | 100-500 attack sequences | Train LSTM (Week 6) |
| 6+ | Continuous outcomes | Train RL agent (continuous) |

---

## **Critical Success Factors:**

### **✅ Must Have by Week 9:**
1. **500+ analyst-labeled alerts** (for XGBoost FP Classifier)
   - True Positive / False Positive labels
   - Severity corrections
   - Action outcomes

2. **100+ historical incidents** (for Root Cause Classifier)
   - Root cause labels
   - Attack sequences

3. **30+ days of normal alerts** (for Isolation Forest)
   - Unlabeled, just normal operations

4. **6+ months alert history** (for Prophet)
   - Hourly alert counts

### **⚠️ Biggest Risk:**
**Not collecting enough labeled feedback by Week 9!**

**Mitigation:**
- Deploy feedback UI Week 1 ✅
- Train analysts on labeling ✅
- Set quota: 60 labels/week ✅
- Gamify: Leaderboard for most helpful labels ✅
- Automate: Pre-fill some fields ✅

---

## **Week-by-Week Checklist:**

### **Week 4:**
- [ ] Isolation Forest trained and deployed
- [ ] Prophet trained and deployed
- [ ] Anomaly scores available for all alerts
- [ ] Attack window forecasts running every 6 hours
- [ ] Feedback count: ~240 labels

### **Week 5:**
- [ ] Attack Chain Detector deployed
- [ ] Heuristic FP Detector deployed (temporary)
- [ ] Root Cause Classifier trained and deployed
- [ ] Cross-device correlation working
- [ ] Feedback count: ~300 labels

### **Week 6:**
- [ ] LSTM Stage Predictor deployed
- [ ] PPO RL Agent deployed
- [ ] LLM loaded and operational
- [ ] All 5 AI Agents functional
- [ ] Feedback count: ~360 labels

### **Week 9: CRITICAL TRAINING WEEK**
- [ ] Collected 500+ labeled alerts ✅
- [ ] XGBoost FP Classifier trained and deployed
- [ ] Isolation Forest retrained with feedback
- [ ] Root Cause Classifier improved
- [ ] All models validated

### **Week 12:**
- [ ] All 8 models in production
- [ ] All 10 capabilities operational
- [ ] All 5 agents working together
- [ ] Continuous learning active
- [ ] MVP LAUNCHED! 🚀

---

**END OF ROADMAP**
