# Quick Training Commands Reference

## Fast Training (Copy-Paste Ready)

### Train All 6 Models in Sequence

```bash
# 1. Anomaly Detector (~10-15 min)
docker exec -it soar-anomaly-detector python -m services.ml.anomaly_detection.train_anomaly_detector

# 2. Attack Stage Predictor (~1 min, rule-based)
docker exec -it soar-attack-stage python -m services.ml.attack_stage.train_attack_stage

# 3. Attack Forecaster (~5-10 min)
docker exec -it soar-attack-forecaster python -m services.ml.attack_forecasting.train_attack_forecaster

# 4. False Positive Detector (~8-12 min)
docker exec -it soar-fp-detector python -m services.ml.false_positive_detection.train_fp_detector

# 5. Asset Risk Evaluator (~5-8 min)
docker exec -it soar-asset-risk python -m services.ml.asset_risk_evaluation.train_asset_risk

# 6. Root Cause Analyzer (~12-18 min)
docker exec -it soar-root-cause python -m services.ml.root_cause_analysis.train_root_cause_analyzer
```

**Total Time**: ~45-60 minutes

---

## Verify All Models Trained

```bash
# Check model files exist
docker exec soar-anomaly-detector ls -lh /models/
docker exec soar-attack-forecaster ls -lh /models/attack_forecaster/
docker exec soar-fp-detector ls -lh /models/fp_detector/
docker exec soar-asset-risk ls -lh /models/asset_risk/
docker exec soar-root-cause ls -lh /models/root_cause/
```

---

## Quick Health Check

```bash
# All should return healthy
curl http://localhost:5001/health
curl http://localhost:5002/health
curl http://localhost:5003/health
curl http://localhost:5004/health
curl http://localhost:5005/health
curl http://localhost:5006/health
```

---

## Training Data Location

**File**: `Attack_Data_Syn/synthetic_wazuh_alerts.json`
- 30,000 alerts
- 90 days of data
- 365 unique assets
- Balanced & unbiased ✅

---

For detailed instructions, see `TRAINING_COMMANDS.md`
