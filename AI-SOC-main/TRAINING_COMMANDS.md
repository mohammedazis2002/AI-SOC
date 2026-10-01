# ML Models Training Commands

## System Setup

### 1. Prerequisites
```bash
# Pull latest code from GitHub
git clone <your-repo-url>
cd soar-platform

# Ensure Docker and Docker Compose are running
docker --version
docker-compose --version

# Start all services
docker-compose up -d

# Verify all 6 ML services are healthy (wait ~1 minute)
docker ps --format "table {{.Names}}\t{{.Status}}" | grep soar-
```

Expected output: All 6 services showing "(healthy)"

---

## Data Preparation

### 2. Load Training Data into MongoDB

```bash
# Copy synthetic data to the backend container
docker cp /path/to/Attack_Data_Syn/synthetic_wazuh_alerts.json soar-backend:/tmp/

# Or if using the ingestion service
# Place the synthetic_wazuh_alerts.json in the data ingestion directory
# The log_processor will automatically pick it up
```

---

## Training Commands (Execute in Order)

### 3. Model 1: Anomaly Detector (Port 5001)

```bash
# Enter container
docker exec -it soar-anomaly-detector bash

# Train the model
python -m services.ml.anomaly_detection.train_anomaly_detector

# Exit container
exit

# Verify model file created
docker exec soar-anomaly-detector ls -lh /models/
```

**Expected Output**: 
- `anomaly_detector_model.pkl` (Isolation Forest)
- `lstm_autoencoder.h5` (LSTM model)
- Training metrics printed

---

### 4. Model 2: Attack Stage Predictor (Port 5002)

```bash
# Enter container
docker exec -it soar-attack-stage bash

# Train the model (if ML-based; otherwise rule-based is pre-configured)
python -m services.ml.attack_stage.train_attack_stage

# Exit container
exit
```

**Note**: This model is primarily rule-based using MITRE mappings. Training is optional for LSTM timing predictor.

---

### 5. Model 3: Attack Forecaster (Port 5003)

```bash
# Enter container
docker exec -it soar-attack-forecaster bash

# Train the Auto-ARIMA model
python -m services.ml.attack_forecasting.train_attack_forecaster

# Exit container
exit

# Verify model file
docker exec soar-attack-forecaster ls -lh /models/attack_forecaster/
```

**Expected Output**:
- `attack_forecaster_model.pkl` (Auto-ARIMA model)
- Best parameters logged

---

### 6. Model 4: False Positive Detector (Port 5004)

```bash
# Enter container
docker exec -it soar-fp-detector bash

# Train the FP detector
python -m services.ml.false_positive_detection.train_fp_detector

# Exit container
exit

# Verify model
docker exec soar-fp-detector ls -lh /models/fp_detector/
```

**Expected Output**:
- `fp_detector_model.pkl` (Random Forest)
- `noisy_rules.json` (learned noisy rules)
- Model accuracy metrics

---

### 7. Model 5: Asset Risk Evaluator (Port 5005)

```bash
# Enter container
docker exec -it soar-asset-risk bash

# Train risk model (builds asset profiles and risk baselines)
python -m services.ml.asset_risk_evaluation.train_asset_risk

# Exit container
exit

# Verify asset profiles
docker exec soar-asset-risk ls -lh /models/asset_risk/
```

**Expected Output**:
- `asset_profiles.json` (365 asset profiles)
- `risk_model.pkl` (if ML-based)
- Asset inventory database populated

---

### 8. Model 6: Root Cause Analyzer (Port 5006)

```bash
# Enter container
docker exec -it soar-root-cause bash

# Train the multi-label classifier
python -m services.ml.root_cause_analysis.train_root_cause_analyzer

# Exit container
exit

# Verify model
docker exec soar-root-cause ls -lh /models/root_cause/
```

**Expected Output**:
- `root_cause_model.pkl` (Multi-Label Random Forest)
- Per-label metrics (14 root cause categories)
- Overall accuracy and F1 scores

---

## Verification

### 9. Test All Models

```bash
# Test each service health
curl http://localhost:5001/health  # Anomaly Detector
curl http://localhost:5002/health  # Attack Stage
curl http://localhost:5003/health  # Attack Forecaster
curl http://localhost:5004/health  # FP Detector
curl http://localhost:5005/health  # Asset Risk
curl http://localhost:5006/health  # Root Cause
```

All should return `{"status": "healthy", ...}`

### 10. Quick Model Test

```bash
# Test Anomaly Detector with sample alert
curl -X POST http://localhost:5001/predict \
  -H "Content-Type: application/json" \
  -d @test_alert.json

# Test FP Detector
curl -X POST http://localhost:5004/detect \
  -H "Content-Type: application/json" \
  -d @test_alert.json
```

---

## Training Data Details

**Source**: `Attack_Data_Syn/synthetic_wazuh_alerts.json`

**Statistics**:
- Total Alerts: 30,000
- Time Period: 90 days
- Unique Assets: 365
- Log Sources: 49
- MITRE Techniques: 796/887 (89.7%)

**Quality**:
- ✅ Severity Balanced (25% each)
- ✅ Tactics Coverage (All 14)
- ✅ Temporal Diversity (Random, business hours, bursts)
- ✅ Asset Diversity (Well-distributed)
- ✅ Unbiased (No concentration)

**Recommended Split**:
- Training: 21,000 alerts (70%)
- Validation: 4,500 alerts (15%)
- Test: 4,500 alerts (15%)

---

## Alternative: Training Scripts (If Not Using Docker)

If running directly on host machine:

```bash
# Set PYTHONPATH
export PYTHONPATH=/path/to/soar-platform/backend:$PYTHONPATH

# Install dependencies
pip install -r backend/requirements.txt

# Train each model
python backend/services/ml/anomaly_detection/train_anomaly_detector.py
python backend/services/ml/attack_stage/train_attack_stage.py
python backend/services/ml/attack_forecasting/train_attack_forecaster.py
python backend/services/ml/false_positive_detection/train_fp_detector.py
python backend/services/ml/asset_risk_evaluation/train_asset_risk.py
python backend/services/ml/root_cause_analysis/train_root_cause_analyzer.py
```

---

## Troubleshooting

### Issue: "ModuleNotFoundError"
```bash
# Ensure PYTHONPATH is set in Docker containers
docker exec soar-anomaly-detector printenv PYTHONPATH
# Should show: /app
```

### Issue: "No training data found"
```bash
# Check MongoDB connection
docker exec soar-anomaly-detector python -c "from pymongo import MongoClient; print(MongoClient('mongodb://mongodb:27017/').list_database_names())"

# Or check if data file is accessible
docker exec soar-anomaly-detector ls -lh /tmp/synthetic_wazuh_alerts.json
```

### Issue: "Model already exists"
```bash
# Remove old models to retrain
docker exec soar-anomaly-detector rm -rf /models/anomaly_detector/
docker-compose restart anomaly-detection
```

---

## Expected Training Times (on typical hardware)

- **Anomaly Detector**: ~10-15 minutes (Isolation Forest + LSTM)
- **Attack Stage**: ~1 minute (rule-based, no training needed)
- **Attack Forecaster**: ~5-10 minutes (Auto-ARIMA parameter search)
- **FP Detector**: ~8-12 minutes (Random Forest + feature engineering)
- **Asset Risk**: ~5-8 minutes (profile building + risk calculation)
- **Root Cause**: ~12-18 minutes (Multi-label classifier, 14 labels)

**Total**: ~45-60 minutes for all 6 models

---

## Post-Training

### Backup Trained Models
```bash
# Create models backup
mkdir -p trained_models_backup
docker cp soar-anomaly-detector:/models/ trained_models_backup/anomaly/
docker cp soar-attack-forecaster:/models/ trained_models_backup/forecaster/
docker cp soar-fp-detector:/models/ trained_models_backup/fp_detector/
docker cp soar-asset-risk:/models/ trained_models_backup/asset_risk/
docker cp soar-root-cause:/models/ trained_models_backup/root_cause/

# Zip backup
tar -czf trained_models_$(date +%Y%m%d).tar.gz trained_models_backup/
```

### Deploy to Production
```bash
# Already running in Docker, models are persisted in volumes
# Just restart services to ensure latest models are loaded
docker-compose restart
```

---

## Summary

✅ All 6 ML services are healthy
✅ Training data is balanced and unbiased  
✅ 30,000 synthetic alerts ready for training
✅ Services accessible on ports 5001-5006

**Ready to train on your other system!** 🚀
