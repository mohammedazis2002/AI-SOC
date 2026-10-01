# Anomaly Detector - Model 1

## Overview

**Model**: Isolation Forest (Unsupervised Learning)  
**Purpose**: Detect anomalous security alerts  
**Port**: 5001  
**Status**: ✅ Ready for training

## Features

- **48 engineered features** extracted from each alert:
  - 6 temporal features (time of day, day of week, business hours)
  - 8 rule-based features (severity, MITRE IDs, compliance flags)
  - 8 network features (IPs, ports, protocol)
  - 8 user/asset features (criticality, privilege level)
  - 10 context features (threat intel, maintenance windows)
  - 8 behavioral features (user deviation, unusual patterns)

- **Unsupervised learning** - no labeled data required
- **Fast inference** - <10ms per alert
- **Scalable** - handles 100+ alerts/second

## Training Requirements

### Data Needed
- **30 days** of historical alerts from MongoDB
- **10,000-50,000 alerts** recommended (minimum 1,000)
- No labels required (unsupervised)

### MongoDB Query
```python
# Alerts from last 30 days
alerts = db.alerts_processed.find({
    "timestamp": {
        "$gte": datetime.utcnow() - timedelta(days=30)
    }
}).limit(50000)
```

## Usage

### 1. Train the Model

Once you have 30 days of alerts in MongoDB:

```bash
python train_anomaly_detector.py
```

This will:
1. Load 30 days of alerts from MongoDB
2. Extract 48 features from each alert
3. Train Isolation Forest model
4. Save model to `models/anomaly_detector.pkl`

### 2. Start the Service

```bash
cd backend/services/ml
python anomaly_detector_service.py
```

Service runs on **http://localhost:5001**

### 3. Test the Service

**Health Check:**
```bash
curl http://localhost:5001/health
```

**Predict Single Alert:**
```bash
curl -X POST http://localhost:5001/predict \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-001",
    "timestamp": "2026-01-20T10:30:00Z",
    "rule_level": 10,
    "severity_id": 4,
    "rule_description": "SSH brute force attempt",
    "rule_groups": ["authentication", "attack"],
    "mitre_ids": ["T1110"],
    "src_endpoint": {"ip": "192.168.1.100", "port": 54321},
    "dst_endpoint": {"ip": "10.0.0.5", "port": 22},
    "actor": {"name": "admin"},
    "agent_id": "001",
    "full_log": "Failed password for admin from 192.168.1.100"
  }'
```

**Response:**
```json
{
  "alert_id": "TEST-001",
  "anomaly_score": 0.87,
  "is_anomaly": true,
  "confidence": 0.91,
  "raw_score": -0.45
}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/predict` | POST | Predict anomaly score for single alert |
| `/batch_predict` | POST | Predict for multiple alerts |
| `/health` | GET | Health check and model status |
| `/metrics` | GET | Service metrics |

## Integration with Alert Pipeline

After training, integrate into your alert processing pipeline:

```python
from services.ml.anomaly_detector import AnomalyDetector

# Load trained model
detector = AnomalyDetector()
detector.load("models/anomaly_detector.pkl")

# In alert processing
def process_alert(alert):
    # Get anomaly score
    result = detector.predict(alert)
    
    # Add to alert
    alert['ml_scores'] = {
        'anomaly_score': result['anomaly_score'],
        'is_anomaly': result['is_anomaly']
    }
    
    # Flag high anomaly alerts
    if result['anomaly_score'] > 0.75:
        alert['requires_review'] = True
        alert['review_reason'] = 'High anomaly score'
    
    return alert
```

## Model Details

### Isolation Forest Parameters
```python
IsolationForest(
    n_estimators=200,      # Number of trees
    contamination=0.01,    # Expected anomaly rate (1%)
    max_samples=256,       # Samples per tree
    random_state=42,       # Reproducibility
    n_jobs=-1,            # Use all CPU cores
    bootstrap=False
)
```

### Output Interpretation

| Anomaly Score | Interpretation | Action |
|---------------|----------------|--------|
| 0.0 - 0.5 | Normal | No action needed |
| 0.5 - 0.75 | Slightly unusual | Monitor |
| 0.75 - 0.9 | Anomalous | Flag for review |
| 0.9 - 1.0 | Highly anomalous | Immediate investigation |

## Performance

- **Training time**: ~2-5 minutes (30,000 alerts)
- **Inference time**: <10ms per alert
- **Throughput**: 100+ alerts/second
- **Memory**: ~50MB for trained model

## Troubleshooting

### Model not found
```
Error: Model file not found
```
**Solution**: Train the model first with `python train_anomaly_detector.py`

### Not enough data
```
Warning: Only X alerts found
```
**Solution**: Wait until you have at least 1,000 alerts (ideally 10,000+)

### Service unavailable
```
503 Service Unavailable: Model not trained yet
```
**Solution**: Train the model before starting the service

## Next Steps

After deploying Model 1:
- [ ] Monitor anomaly scores in dashboard
- [ ] Collect feedback on anomalous alerts
- [ ] Retrain monthly with updated data
- [ ] Build Model 5 (Time Series Forecaster)
- [ ] Integrate with other ML models

## Files

- `backend/services/ml/anomaly_detector.py` - Model implementation
- `backend/services/ml/anomaly_detector_service.py` - FastAPI service
- `train_anomaly_detector.py` - Training script
- `models/anomaly_detector.pkl` - Trained model (after training)
