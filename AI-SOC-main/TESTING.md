# SOAR Platform - Testing Commands

## Prerequisites

Ensure Docker services are running:
```powershell
cd "c:\Users\Shruthi Kannan\Documents\SOAR\soar-platform"
docker-compose ps
```

Expected services: mongodb, redis, qdrant, ollama, prometheus, grafana

---

## 1. Test Wazuh Mapper (Logical/Rule-Based)

### Quick Test
```powershell
python test_wazuh_mapper.py
```

### What it does:
- Loads `backend/examples/wazuh_alert_example.json`
- Maps to ULF format using rule-based logic
- Shows severity, finding, endpoints, observables
- Saves output to `test_wazuh_mapper_output.json`

### Expected Output:
```
✅ MAPPING SUCCESSFUL
📊 ULF Alert:
   Alert ID: SOAR-20260113-XXXXXXXX
   Severity: High (4)
   Finding: <Rule description>
   Source: wazuh
```

---

## 2. Test AI Mapper (LLM-Based)

### Prerequisites
Ensure Ollama has the mistral model:
```powershell
docker-compose exec ollama ollama list
```

If mistral is not listed:
```powershell
docker-compose exec ollama ollama pull mistral:latest
```

### Quick Test
```powershell
python test_ai_mapper.py
```

### What it does:
- Tests 4 different log formats
- Uses Ollama + Mistral to analyze logs
- Converts AI analysis to ULF format
- Shows confidence scores and recommendations
- Saves results to `test_ai_mapper_output.json`

### Expected Output:
```
✅ AI Mapping Successful
   Alert ID: SOAR-20260113-XXXXXXXX
   Finding: SSH Brute Force Attempt
   Severity: High (4)
   Confidence: 0.85
   
📊 AI Analysis:
   Attack Type: brute_force
   Category: authentication
   Recommended Action: Block source IP
```

---

## 3. Test via API (End-to-End)

### Start the API
```powershell
# In one terminal
cd backend
python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### Test Wazuh Webhook
```powershell
# In another terminal
curl -X POST http://localhost:8000/api/v1/alerts/webhook/wazuh `
  -H "Content-Type: application/json" `
  -H "X-API-Key: wazuh-api-key-12345" `
  -d "@backend/examples/wazuh_alert_example.json"
```

### Test Generic Webhook (AI Mapper)
```powershell
# Create a test log file
echo '{"message": "Failed login from 1.2.3.4", "timestamp": "2024-01-15T10:00:00Z"}' > test_log.json

curl -X POST http://localhost:8000/api/v1/alerts/webhook/custom `
  -H "Content-Type: application/json" `
  -H "X-API-Key: custom-api-key-11111" `
  -d "@test_log.json"
```

### Check Health
```powershell
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "components": {
    "database": {"status": "healthy"},
    "queue": {"status": "healthy"}
  }
}
```

---

## 4. Verify Queue (Redis)

### Check if alerts are in queue
```powershell
docker-compose exec redis redis-cli -a <your-redis-password>
```

Inside Redis CLI:
```redis
# Check queue length
XLEN alerts:incoming
XLEN alerts:priority

# Read latest message
XREAD COUNT 1 STREAMS alerts:incoming 0

# Check consumer group
XINFO GROUPS alerts:incoming
```

---

## 5. Verify Database (MongoDB)

### Check if alerts are stored
```powershell
docker-compose exec mongodb mongosh -u soar_user -p <your-password> soar_db
```

Inside MongoDB shell:
```javascript
// Count alerts
db.alerts_processed.countDocuments()

// View latest alert
db.alerts_processed.find().sort({ingestion_timestamp: -1}).limit(1).pretty()

// Search by severity
db.alerts_processed.find({severity_id: {$gte: 4}}).count()

// Search by source
db.alerts_processed.find({siem_source: "wazuh"}).count()
```

---

## 6. Initialize Database (First Time)

### Run inside Docker container
```powershell
docker-compose exec api python scripts/setup/init_db.py
```

This creates:
- All collections
- Indexes for performance
- TTL indexes for data retention

---

## Troubleshooting

### Ollama not responding
```powershell
# Check Ollama logs
docker-compose logs ollama

# Restart Ollama
docker-compose restart ollama

# Pull model again
docker-compose exec ollama ollama pull mistral:latest
```

### MongoDB connection failed
```powershell
# Check MongoDB logs
docker-compose logs mongodb

# Restart MongoDB
docker-compose restart mongodb
```

### Redis connection failed
```powershell
# Check Redis logs
docker-compose logs redis

# Test Redis connection
docker-compose exec redis redis-cli ping
```

### API won't start
```powershell
# Check for port conflicts
netstat -ano | findstr :8000

# Check backend logs
cd backend
python -m uvicorn api.main:app --reload
```

---

## Quick Test All

Run all tests in sequence:
```powershell
# 1. Test Wazuh mapper
python test_wazuh_mapper.py

# 2. Test AI mapper (requires Ollama)
python test_ai_mapper.py

# 3. Start API and test
cd backend
python -m uvicorn api.main:app --reload
```

Then in another terminal:
```powershell
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/v1/alerts/webhook/wazuh `
  -H "Content-Type: application/json" `
  -H "X-API-Key: wazuh-api-key-12345" `
  -d "@backend/examples/wazuh_alert_example.json"
```
