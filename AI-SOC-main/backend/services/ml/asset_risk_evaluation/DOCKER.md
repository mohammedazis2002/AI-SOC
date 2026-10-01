# Model 5 Asset Risk Evaluation - Docker Setup

## ✅ Integrated with Docker Compose!

Model 5 has been added as a dedicated service in `docker-compose.yml`

### Service Configuration

```yaml
asset-risk-evaluation:
  container: soar-asset-risk
  port: 5005
  dependencies: MongoDB
  health-check: http://localhost:5005/health
```

---

## Running with Docker

### 1. Start All Services (Including Model 5)

```bash
docker-compose up -d
```

This starts:
- MongoDB (port 27017)
- Redis (port 6379) 
- Ollama (port 11434)
- Main API (port 8000)
- **Asset Risk Evaluation (port 5005)** ← Model 5
- Prometheus, Grafana, etc.

### 2. Start Only Model 5

```bash
docker-compose up -d asset-risk-evaluation
```

### 3. View Logs

```bash
# All services
docker-compose logs -f

# Model 5 only
docker-compose logs -f asset-risk-evaluation

# Last 100 lines
docker-compose logs --tail=100 asset-risk-evaluation
```

### 4. Check Service Status

```bash
docker-compose ps

# Should show:
# NAME                STATUS        PORTS
# soar-asset-risk     Up (healthy)  0.0.0.0:5005->5005/tcp
```

### 5. Health Check

```bash
# From host
curl http://localhost:5005/health

# From inside container
docker-compose exec asset-risk-evaluation curl http://localhost:5005/health
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
  }
}
```

---

## Test Risk Assessment

### From Host Machine

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

### From Another Container

```bash
docker-compose exec api curl http://asset-risk-evaluation:5005/assess_risk \
  -H "Content-Type: application/json" \
  -d '{"alert": {...}}'
```

---

## Environment Variables

Set in `.env` file at project root:

```bash
# MongoDB (shared with other services)
MONGODB_USERNAME=soar_user
MONGODB_PASSWORD=your_password
MONGODB_DATABASE=soar_db

# Model 5 specific (optional)
MTLS_SERVICE_URL=http://mtls-service:5006
CORRELATION_ENGINE_URL=http://correlation-engine:5007
VULN_CACHE_DAYS=7
INCIDENT_HISTORY_DAYS=90
```

---

## Interactive API Documentation

Once running, open browser:

**http://localhost:5005/docs**

This provides:
- Interactive API testing
- Request/response schemas
- Try it out functionality

---

## Service Management

### Restart Model 5

```bash
docker-compose restart asset-risk-evaluation
```

### Stop Model 5

```bash
docker-compose stop asset-risk-evaluation
```

### Rebuild After Code Changes

```bash
docker-compose up -d --build asset-risk-evaluation
```

### View Resource Usage

```bash
docker stats soar-asset-risk
```

---

## Integration with Other Services

Model 5 automatically integrates with:

1. **MongoDB** (port 27017)
   - Shared database connection
   - Collections: asset_profiles, asset_vulnerabilities, incidents, etc.

2. **Internal Network** (soar-network)
   - Accessible from other containers: `http://asset-risk-evaluation:5005`
   - Main API can call Model 5: 
     ```python
     response = requests.post(
         "http://asset-risk-evaluation:5005/assess_risk",
         json={"alert": ocsf_alert}
     )
     ```

3. **Future Services** (when implemented)
   - mTLS Service (port 5006)
   - Correlation Engine (port 5007)

---

## Troubleshooting

### MongoDB Connection Issues

```bash
# Check MongoDB is running
docker-compose ps mongodb

# Check MongoDB logs
docker-compose logs mongodb

# Verify credentials in .env
cat .env | grep MONGODB
```

### Port Already in Use

```bash
# Check what's using port 5005
netstat -ano | findstr :5005

# Option 1: Stop conflicting service
# Option 2: Change port in docker-compose.yml:
#   ports:
#     - "5006:5005"  # Maps host:5006 -> container:5005
```

### Service Not Starting

```bash
# View detailed logs
docker-compose logs --tail=50 asset-risk-evaluation

# Check health status
docker-compose ps asset-risk-evaluation

# Rebuild container
docker-compose up -d --build asset-risk-evaluation
```

### Cannot Access from Host

```bash
# Verify port mapping
docker-compose ps asset-risk-evaluation

# Check firewall
# Windows: Allow port 5005 in Windows Firewall

# Test from inside container
docker-compose exec asset-risk-evaluation curl localhost:5005/health
```

---

## Advantages of Docker Setup

✅ **Isolated Environment**: No Python version conflicts
✅ **Automatic Restarts**: Service restarts if it crashes
✅ **Consistent Configuration**: Same setup everywhere
✅ **Easy Scaling**: Can run multiple instances
✅ **Health Monitoring**: Docker tracks service health
✅ **Network Isolation**: Secure inter-service communication
✅ **MongoDB Included**: No separate installation needed

---

## Development vs Production

### Development (Current Setup)

```yaml
volumes:
  - ./backend:/app  # Live code reload
command: python -m services.ml.asset_risk_evaluation.start_service
```

Changes to Python files are reflected immediately (container uses host files).

### Production (Recommended)

Remove volume mount and rebuild:

```yaml
# Comment out in production:
# volumes:
#   - ./backend:/app

# Code is baked into container
```

Then:
```bash
docker-compose build asset-risk-evaluation
docker-compose up -d asset-risk-evaluation
```

---

## Complete Docker Workflow

```bash
# 1. Start all services
docker-compose up -d

# 2. Check status
docker-compose ps

# 3. View Model 5 logs
docker-compose logs -f asset-risk-evaluation

# 4. Test service
curl http://localhost:5005/health

# 5. Open API docs in browser
# http://localhost:5005/docs

# 6. Make code changes (auto-reload in dev mode)

# 7. View logs for errors
docfor logs --tail=100 asset-risk-evaluation

# 8. When done
docker-compose down
```

---

## Summary

**Model 5 is now fully Dockerized!** 🐳

- ✅ Added to `docker-compose.yml`
- ✅ Runs on port 5005
- ✅ Integrated with MongoDB
- ✅ Health checks configured
- ✅ Auto-restarts enabled
- ✅ Part of soar-network

**No need to run `python start_service.py` manually anymore!**

Just use: `docker-compose up -d`
