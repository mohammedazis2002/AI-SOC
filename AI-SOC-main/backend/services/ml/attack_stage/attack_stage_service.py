"""
Attack Stage Predictor API Service (Model 2)

FastAPI service exposing attack stage prediction and unmapped alert queue

Port: 5003

Endpoints:
- POST /predict - Predict attack stage and timing
- POST /enrich_and_predict - Enrich MITRE data then predict
- GET /queue/unmapped - Get unmapped alerts for review
- POST /queue/unmapped/:id/review - Submit analyst review
- POST /queue/unmapped/:id/reject - Reject unmapped alert
- GET /queue/stats - Get queue statistics
- GET /health - Health check
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query, Path
from pydantic import BaseModel, Field
from pymongo import MongoClient
import os

from backend.services.ml.attack_stage.stage_predictor import AttackStagePredictor
from backend.services.ml.attack_stage.mitre_enricher import MITREEnricher
from backend.services.ml.attack_stage.unmapped_queue import UnmappedAlertQueue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Attack Stage Predictor API",
    description="Model 2: Attack Stage Prediction with MITRE enrichment and timing forecasts",
    version="2.0"
)

# Initialize MongoDB
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
mongo_client = MongoClient(MONGO_URI)

# Initialize Model 2 components
predictor = AttackStagePredictor()
enricher = MITREEnricher(pattern_library_path='data/mitre/attack_patterns.json')
queue = UnmappedAlertQueue(mongo_client)

logger.info("Attack Stage Predictor API initialized successfully")


# === Pydantic Models ===

class StagePredictionRequest(BaseModel):
    """Request model for stage prediction"""
    alert: Dict[str, Any] = Field(..., description="OCSF alert object (must have MITRE enrichment)")


class EnrichAndPredictRequest(BaseModel):
    """Request model for enrichment + prediction"""
    alert: Dict[str, Any] = Field(..., description="OCSF alert object")
    force_queue_if_failed: bool = Field(default=True, description="Queue alert if enrichment fails")


class ReviewRequest(BaseModel):
    """Request model for analyst review of unmapped alert"""
    analyst_mitre: Dict[str, Any] = Field(..., description="MITRE mapping provided by analyst")
    analyst_id: str = Field(..., description="ID of reviewing analyst")
    notes: Optional[str] = Field(None, description="Optional notes")


class RejectRequest(BaseModel):
    """Request model for rejecting unmapped alert"""
    analyst_id: str = Field(..., description="ID of reviewing analyst")
    reason: str = Field(..., description="Reason for rejection")


class StagePredictionResponse(BaseModel):
    """Response model for stage prediction"""
    model: str
    version: str
    current_stage: Optional[str]
    stage_number: int
    confidence: float
    action: str
    severity: str
    priority: Optional[str] = None
    message: str
    next_stages: Optional[List[Dict[str, Any]]] = None
    recommended_actions: Optional[List[str]] = None
    escalation: Optional[Dict[str, Any]] = None
    skip_prediction: Optional[bool] = None


# === API Endpoints ===

@app.post("/predict", response_model=StagePredictionResponse)
async def predict_stage(request: StagePredictionRequest):
    """
    Predict attack stage and timing
    
    **NOTE:** Alert must already have MITRE enrichment!
    Use /enrich_and_predict if enrichment is needed.
    """
    
    try:
        result = predictor.predict(request.alert)
        return result
    
    except Exception as e:
        logger.error(f"Prediction error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/enrich_and_predict")
async def enrich_and_predict(request: EnrichAndPredictRequest):
    """
    Enrich alert with MITRE data, then predict stage
    
    If enrichment fails and force_queue_if_failed=True, alert is queued.
    """
    
    try:
        alert = request.alert
        
        # Step 1: Attempt MITRE enrichment
        mitre_data, enrichment_attempts = enricher.enrich(alert)
        
        # Step 2: If enrichment succeeded, predict
        if mitre_data:
            # Add MITRE enrichment to alert
            if 'enrichments' not in alert:
                alert['enrichments'] = {}
            alert['enrichments']['mitre'] = mitre_data
            
            # Predict stage
            prediction = predictor.predict(alert)
            
            return {
                'status': 'success',
                'enrichment_method': mitre_data.get('method'),
                'prediction': prediction
            }
        
        # Step 3: Enrichment failed
        else:
            if request.force_queue_if_failed:
                # Queue alert for analyst review
                queue_id = queue.add_to_queue(
                    alert=alert,
                    enrichment_attempts=enrichment_attempts,
                    reason="All MITRE enrichment methods failed"
                )
                
                return {
                    'status': 'queued',
                    'queue_id': queue_id,
                    'message': 'Alert queued for analyst review - MITRE enrichment failed',
                    'enrichment_attempts': enrichment_attempts
                }
            else:
                return {
                    'status': 'failed',
                    'message': 'MITRE enrichment failed',
                    'enrichment_attempts': enrichment_attempts
                }
    
    except Exception as e:
        logger.error(f"Enrich and predict error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/queue/unmapped")
async def get_unmapped_alerts(
    priority: Optional[str] = Query(None, description="Filter by priority (critical|high|medium|low)"),
    limit: int = Query(50, description="Maximum number of results", ge=1, le=200)
):
    """
    Get pending unmapped alerts for analyst review
    """
    
    try:
        alerts = queue.get_pending_alerts(priority=priority, limit=limit)
        return {
            'count': len(alerts),
            'alerts': alerts
        }
    
    except Exception as e:
        logger.error(f"Queue retrieval error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/queue/unmapped/{queue_id}/review")
async def review_unmapped_alert(
    queue_id: str = Path(..., description="Queue entry ID"),
    request: ReviewRequest = ...
):
    """
    Submit analyst review with MITRE mapping
    
    Once reviewed, the alert can be reprocessed with the analyst-provided MITRE data.
    """
    
    try:
        success = queue.submit_review(
            queue_id=queue_id,
            analyst_mitre=request.analyst_mitre,
            analyst_id=request.analyst_id,
            notes=request.notes
        )
        
        if success:
            return {
                'status': 'success',
                'message': 'Review submitted successfully',
                'queue_id': queue_id
            }
        else:
            raise HTTPException(status_code=404, detail="Queue entry not found")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Review submission error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/queue/unmapped/{queue_id}/reject")
async def reject_unmapped_alert(
    queue_id: str = Path(..., description="Queue entry ID"),
    request: RejectRequest = ...
):
    """
    Reject alert as not attack-related
    """
    
    try:
        success = queue.reject_alert(
            queue_id=queue_id,
            analyst_id=request.analyst_id,
            reason=request.reason
        )
        
        if success:
            return {
                'status': 'success',
                'message': 'Alert rejected successfully',
                'queue_id': queue_id
            }
        else:
            raise HTTPException(status_code=404, detail="Queue entry not found")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Rejection error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/queue/stats")
async def get_queue_stats():
    """
    Get unmapped alert queue statistics
    """
    
    try:
        stats = queue.get_queue_stats()
        enrichment_stats = enricher.get_enrichment_stats()
        
        return {
            'queue': stats,
            'enrichment': enrichment_stats
        }
    
    except Exception as e:
        logger.error(f"Stats retrieval error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/queue/reviewed_mappings")
async def get_reviewed_mappings(
    limit: int = Query(100, description="Maximum number of results", ge=1, le=500)
):
    """
    Get analyst-reviewed MITRE mappings
    
    Useful for training ML models or building pattern libraries
    """
    
    try:
        mappings = queue.get_reviewed_mappings(limit=limit)
        return {
            'count': len(mappings),
            'mappings': mappings
        }
    
    except Exception as e:
        logger.error(f"Mappings retrieval error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    
    return {
        'status': 'healthy',
        'service': 'attack_stage_predictor',
        'model': 'Model 2',
        'version': '2.0',
        'features': {
            'full_14_tactics': True,
            'no_unknown_stages': True,
            'critical_stage_escalation': True,
            'lstm_timing': predictor.lstm_predictor is not None,
            'enhanced_enrichment': True
        },
        'timestamp': datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5002)
