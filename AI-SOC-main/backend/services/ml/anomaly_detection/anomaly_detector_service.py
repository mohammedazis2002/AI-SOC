"""
Anomaly Detector Service - Model 1
FastAPI microservice for anomaly detection

Endpoints:
- POST /predict - Predict anomaly score for single alert
- POST /batch_predict - Predict for multiple alerts
- GET /health - Health check
- GET /metrics - Service metrics
"""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import uvicorn
import logging
from pathlib import Path
import sys

# Add repo root (/app) to path so `backend.*` imports work when executed as a module.
sys.path.append(str(Path(__file__).resolve().parents[4]))

from backend.services.ml.anomaly_detection.anomaly_detector import AnomalyDetector

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Anomaly Detector Service",
    description="ML Model 1: Isolation Forest for anomaly detection",
    version="1.0.0"
)

# Global detector instance
detector = None


# Pydantic models
class AlertInput(BaseModel):
    """Input schema for alert"""
    alert_id: str
    timestamp: str
    rule_level: int | None = None
    severity_id: int | None = None
    rule_description: str | None = None
    rule_groups: List[str] = Field(default_factory=list)
    mitre_ids: List[str] = Field(default_factory=list)
    src_endpoint: Dict[str, Any] = Field(default_factory=dict)
    dst_endpoint: Dict[str, Any] = Field(default_factory=dict)
    actor: Dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None
    full_log: str | None = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "SOAR-20260120-abc123",
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
            }
        }


class AnomalyResponse(BaseModel):
    """Response schema for anomaly prediction"""
    alert_id: str
    anomaly_score: float = Field(..., description="Anomaly probability (0-1, higher = more anomalous)")
    is_anomaly: bool = Field(..., description="True if anomaly score > 0.75")
    confidence: float = Field(..., description="Model confidence")
    raw_score: float = Field(..., description="Raw Isolation Forest score")


class BatchAnomalyResponse(BaseModel):
    """Response for batch prediction"""
    predictions: List[AnomalyResponse]
    total_alerts: int
    anomaly_count: int


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    service: str
    model_loaded: bool
    model_trained: bool


@app.on_event("startup")
async def startup_event():
    """Load model on startup"""
    global detector
    
    logger.info("Starting Anomaly Detector Service...")
    
    try:
        detector = AnomalyDetector()
        detector.load("models/anomaly_detector.pkl")
        logger.info("✅ Model loaded successfully")
    except FileNotFoundError:
        logger.warning("⚠️  Model file not found. Service running but not ready for predictions.")
        logger.warning("   Train the model first: python train_anomaly_detector.py")
        detector = AnomalyDetector()  # Initialize without loading
    except Exception as e:
        logger.error(f"❌ Error loading model: {e}")
        detector = AnomalyDetector()


@app.post("/predict", response_model=AnomalyResponse, status_code=status.HTTP_200_OK)
async def predict(alert: AlertInput):
    """
    Predict anomaly score for a single alert
    
    Returns anomaly score between 0.0 (normal) and 1.0 (anomalous)
    """
    if not detector or not detector.trained:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not trained yet. Please train the model first."
        )
    
    try:
        # Convert Pydantic model to dict
        alert_dict = alert.dict()
        
        # Predict
        result = detector.predict(alert_dict)
        
        return AnomalyResponse(
            alert_id=alert.alert_id,
            anomaly_score=result['anomaly_score'],
            is_anomaly=result['is_anomaly'],
            confidence=result['confidence'],
            raw_score=result['raw_score']
        )
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}"
        )


@app.post("/batch_predict", response_model=BatchAnomalyResponse)
async def batch_predict(alerts: List[AlertInput]):
    """
    Predict anomaly scores for multiple alerts
    """
    if not detector or not detector.trained:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not trained yet. Please train the model first."
        )
    
    try:
        predictions = []
        anomaly_count = 0
        
        for alert in alerts:
            alert_dict = alert.dict()
            result = detector.predict(alert_dict)
            
            pred = AnomalyResponse(
                alert_id=alert.alert_id,
                anomaly_score=result['anomaly_score'],
                is_anomaly=result['is_anomaly'],
                confidence=result['confidence'],
                raw_score=result['raw_score']
            )
            
            predictions.append(pred)
            if pred.is_anomaly:
                anomaly_count += 1
        
        return BatchAnomalyResponse(
            predictions=predictions,
            total_alerts=len(alerts),
            anomaly_count=anomaly_count
        )
    
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch prediction failed: {str(e)}"
        )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy" if (detector and detector.trained) else "not_ready",
        service="anomaly-detector",
        model_loaded=detector is not None,
        model_trained=detector.trained if detector else False
    )


@app.get("/metrics")
async def get_metrics():
    """Get service metrics"""
    return {
        "service": "anomaly-detector",
        "model": "Isolation Forest",
        "features": len(detector.feature_names) if detector else 0,
        "trained": detector.trained if detector else False,
        "contamination": detector.model.contamination if detector else None
    }


if __name__ == "__main__":
    uvicorn.run(
        "backend.services.ml.anomaly_detection.anomaly_detector_service:app",
        host="0.0.0.0",
        port=5001,
        reload=True,
        log_level="info"
    )
