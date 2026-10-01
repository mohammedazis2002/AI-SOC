# Asset Risk Evaluation - Quick Start Guide

## ✅ Service Ready to Run!

### How to Start the Service

From the `asset_risk_evaluation` folder:

```bash
cd backend/services/ml/asset_risk_evaluation
python start_service.py
```

Or from anywhere in the project:

```bash
python backend/services/ml/asset_risk_evaluation/start_service.py
```

### What You'll See

```
============================================================
🚀 Starting Asset Risk Evaluation Service
============================================================
📍 Service URL: http://0.0.0.0:5005
📚 API Docs: http://localhost:5005/docs
💾 MongoDB: mongodb://localhost:27017
============================================================
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:5005
```

### Test the Service

**1. Health Check:**
```bash
curl http://localhost:5005/health
```

Expected response:
```json
{
  "status": "healthy",
  "components": {
    "compliance_detector": "ok",
    "asset_detector": "ok",
    "risk_calculator": "ok",
    "mongodb": "ok"
  },
  "timestamp": "2024-02-04T06:00:00"
}
```

**2. Assess Risk (Test Alert):**
```bash
curl -X POST http://localhost:5005/assess_risk \
  -H "Content-Type: application/json" \
  -d '{
    "alert": {
      "device": {
        "hostname": "payment-gateway-01",
        "ip": "10.0.1.50",
        "os": {"name": "Ubuntu 20.04"}
      },
      "dst_endpoint": {
        "domain": "api.stripe.com",
        "port": 443
      }
    }
  }'
```

**3. Interactive API Docs:**

Open browser: http://localhost:5005/docs

### Configuration

Create `.env` file in the `asset_risk_evaluation` folder:

```bash
# MongoDB (required for persistence)
MONGO_URI=mongodb://localhost:27017
MONGO_DATABASE=soar

# Service settings
ASSET_RISK_PORT=5005

# Risk factor weights (optional, defaults shown)
CRITICALITY_WEIGHT=0.25
VULNERABILITY_WEIGHT=0.30
EXPOSURE_WEIGHT=0.20
INCIDENT_WEIGHT=0.15
THREAT_INTEL_WEIGHT=0.10
```

### Common Issues

**Issue: MongoDB connection failed**
```
⚠️ MongoDB not available: [Errno 111] Connection refused
```
Solution: MongoDB is optional. Service will run without persistence.
To fix: Install and start MongoDB, or update MONGO_URI in `.env`

**Issue: Port 5005 already in use**
```
OSError: [Errno 48] Address already in use
```
Solution: Change port in `.env` or `start_service.py`:
```python
port=5006  # Change to available port
```

### Files Created

✅ `start_service.py` - Standalone startup script (fixed imports)
✅ All 23 model files present in folder
✅ External folder can be safely deleted

### Next Steps

1. **Start MongoDB** (optional but recommended):
   ```bash
   mongod --dbpath /path/to/data
   ```

2. **Run the service:**
   ```bash
   python start_service.py
   ```

3. **Test with sample alert** (see above)

4. **Integrate with alert pipeline** (Phase 3)
