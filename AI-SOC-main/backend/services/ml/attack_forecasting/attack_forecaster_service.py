"""
Attack Forecaster Service - Model 5
FastAPI microservice for attack window forecasting

Endpoints:
- GET /forecast?hours=24 - Get forecast for next N hours
- GET /next_risk_window - Get next high-risk window
- GET /health - Health check
- GET /metrics - Service metrics
"""

from fastapi import FastAPI, HTTPException, status, Query
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import uvicorn
import logging
from pathlib import Path
import sys

# Add repo root (/app) to path so `backend.*` imports work when executed as a module.
sys.path.append(str(Path(__file__).resolve().parents[4]))

from backend.services.ml.attack_forecasting.attack_forecaster import MultivariateForecast

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Attack Forecaster Service",
    description="ML Model 5: Auto-ARIMA/SARIMAX time series forecaster for attack window prediction",
    version="1.0.0"
)

# Global forecaster instance
forecaster = None


# Pydantic models
class Prediction(BaseModel):
    """Single hour prediction"""
    timestamp: str
    predicted_alerts: int
    confidence_lower: int
    confidence_upper: int
    risk_level: str = Field(..., description="low, medium, high, or critical")
    hour_of_day: int
    day_of_week: str


class ForecastResponse(BaseModel):
    """Forecast response"""
    forecast_horizon_hours: int
    forecast_start: str
    forecast_end: str
    predictions: List[Prediction]
    high_risk_windows: List[Prediction]
    statistics: Dict[str, Any]


class RiskWindowResponse(BaseModel):
    """Next risk window response"""
    has_risk: bool
    message: str | None = None
    timestamp: str | None = None
    risk_level: str | None = None
    predicted_alerts: int | None = None
    hours_until: float | None = None
    recommendation: str | None = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    service: str
    model_loaded: bool
    model_trained: bool
    train_date_range: str | None = None


@app.on_event("startup")
async def startup_event():
    """Load model on startup"""
    global forecaster
    
    logger.info("Starting Attack Forecaster Service...")
    
    try:
        forecaster = MultivariateForecast()
        forecaster.load("models/prophet_forecaster.pkl")
        logger.info("✅ Model loaded successfully")
    except FileNotFoundError:
        logger.warning("⚠️  Model file not found. Service running but not ready for predictions.")
        logger.warning("   Train the model first: python train_attack_forecaster.py")
        forecaster = MultivariateForecast()  # Initialize without loading
    except Exception as e:
        logger.error(f"❌ Error loading model: {e}")
        forecaster = MultivariateForecast()


@app.get("/forecast", response_model=ForecastResponse)
async def get_forecast(
    hours: int = Query(24, ge=1, le=168, description="Hours to forecast (1-168)")
):
    """
    Get attack forecast for next N hours
    
    Returns hourly predictions with confidence intervals and risk levels
    """
    if not forecaster or not forecaster.trained:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not trained yet. Please train the model first."
        )
    
    try:
        forecast = forecaster.forecast(hours_ahead=hours)
        return ForecastResponse(**forecast)
    
    except Exception as e:
        logger.error(f"Forecast error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forecast failed: {str(e)}"
        )


@app.get("/next_risk_window", response_model=RiskWindowResponse)
async def get_next_risk_window():
    """
    Get the next upcoming high-risk time window
    
    Returns details of the next high-risk period with recommendations
    """
    if not forecaster or not forecaster.trained:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not trained yet. Please train the model first."
        )
    
    try:
        risk_window = forecaster.get_next_high_risk_window()
        return RiskWindowResponse(**risk_window)
    
    except Exception as e:
        logger.error(f"Risk window error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Risk window check failed: {str(e)}"
        )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    train_range = None
    if forecaster and forecaster.trained:
        train_range = f"{forecaster.train_start_date} to {forecaster.train_end_date}"
    
    return HealthResponse(
        status="healthy" if (forecaster and forecaster.trained) else "not_ready",
        service="attack-forecaster",
        model_loaded=forecaster is not None,
        model_trained=forecaster.trained if forecaster else False,
        train_date_range=train_range
    )


@app.get("/metrics")
async def get_metrics():
    """Get service metrics"""
    metrics = {
        "service": "attack-forecaster",
        "model": "Auto-ARIMA/SARIMAX",
        "trained": forecaster.trained if forecaster else False
    }
    
    if forecaster and forecaster.trained:
        metrics.update({
            "train_start": str(forecaster.train_start_date),
            "train_end": str(forecaster.train_end_date)
        })
    
    return metrics


if __name__ == "__main__":
    uvicorn.run(
        "backend.services.ml.attack_forecasting.attack_forecaster_service:app",
        host="0.0.0.0",
        port=5003,
        reload=True,
        log_level="info"
    )
