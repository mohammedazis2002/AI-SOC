"""
False Positive Detector Service (Model 6)

FastAPI service for false positive detection
Port: 5006

Endpoints:
- POST /detect - Analyze single alert
- POST /batch-detect - Analyze multiple alerts
- GET /noisy-rules - Get noisy rules list
- POST /noisy-rules/refresh - Update noisy rules
- POST /feedback - Submit analyst feedback
- GET /health - Health check
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

from services.ml.false_positive_detection.fp_detector import FalsePositiveDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="False Positive Detector API",
    description="ML-powered false positive detection for security alerts",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize detector
detector = FalsePositiveDetector()


# === Request/Response Models ===

class DetectRequest(BaseModel):
    alert: Dict[str, Any]

class BatchDetectRequest(BaseModel):
    alerts: List[Dict[str, Any]]

class FeedbackRequest(BaseModel):
    alert_id: str
    model_prediction: str  # "false_positive" or "true_positive"
    analyst_verdict: str  # "false_positive" or "true_positive"
    analyst: str
    reason: Optional[str] = None

class NoisyRulesRefreshRequest(BaseModel):
    min_alerts: int = 50
    fp_threshold: float = 0.6


# === Endpoints ===

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "fp-detector",
        "version": "1.0.0",
        "ml_model_loaded": detector.ml_model is not None,
        "model_metadata": detector.model_metadata,
        "timestamp": datetime.now().isoformat()
    }


@app.post("/detect")
async def detect_fp(request: DetectRequest):
    """
    Detect if alert is a false positive
    
    Args:
        alert: OCSF ULF alert dictionary
        
    Returns:
        {
            'alert_id': str,
            'fp_score': float (0-1),
            'confidence': float (0-1),
            'method': str,
            'reasons': list,
            'recommendation': dict,
            'similar_fps': list
        }
    """
    try:
        result = detector.detect(request.alert)
        
        return {
            'alert_id': request.alert.get('alert_id', 'unknown'),
            **result
        }
    
    except Exception as e:
        logger.error(f"Detection failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/batch-detect")
async def batch_detect_fp(request: BatchDetectRequest):
    """
    Detect FPs in batch
    
    Args:
        alerts: List of OCSF ULF alerts
        
    Returns:
        {
            'total': int,
            'results': list,
            'summary': dict
        }
    """
    try:
        results = detector.batch_detect(request.alerts)
        
        # Calculate summary stats
        fp_count = sum(1 for r in results if r['fp_score'] >= 0.7)
        auto_close_count = sum(1 for r in results if r['recommendation']['action'] == 'auto_close')
        suppress_count = sum(1 for r in results if r['recommendation']['action'] == 'suppress')
        
        return {
            'total': len(results),
            'results': results,
            'summary': {
                'likely_fps': fp_count,
                'auto_close_recommended': auto_close_count,
                'suppress_recommended': suppress_count,
                'investigate_recommended': len(results) - auto_close_count - suppress_count
            }
        }
    
    except Exception as e:
        logger.error(f"Batch detection failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/noisy-rules")
async def get_noisy_rules():
    """
    Get list of known noisy rules
    
    Returns:
        {
            'count': int,
            'rules': list,
            'last_updated': str
        }
    """
    try:
        noisy_rules = list(detector.db.noisy_rules.find({}).sort('fp_rate', -1))
        
        # Remove MongoDB _id
        for rule in noisy_rules:
            rule['_id'] = str(rule['_id'])
        
        last_updated = None
        if noisy_rules:
            last_updated = noisy_rules[0].get('last_updated', datetime.now()).isoformat()
        
        return {
            'count': len(noisy_rules),
            'rules': noisy_rules,
            'last_updated': last_updated
        }
    
    except Exception as e:
        logger.error(f"Failed to get noisy rules: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/noisy-rules/refresh")
async def refresh_noisy_rules(request: NoisyRulesRefreshRequest):
    """
    Refresh noisy rules list from historical data
    
    Args:
        min_alerts: Minimum alert count (default: 50)
        fp_threshold: FP rate threshold (default: 0.6)
        
    Returns:
        {
            'count': int,
            'rules': list,
            'refreshed_at': str
        }
    """
    try:
        noisy_rules = detector.update_noisy_rules(
            min_alerts=request.min_alerts,
            fp_threshold=request.fp_threshold
        )
        
        return {
            'count': len(noisy_rules),
            'rules': noisy_rules,
            'refreshed_at': datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to refresh noisy rules: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/feedback")
async def submit_feedback(request: FeedbackRequest):
    """
    Submit analyst feedback on FP prediction
    
    Used for continuous learning and model improvement
    
    Args:
        alert_id: Alert identifier
        model_prediction: What model predicted
        analyst_verdict: What analyst decided
        analyst: Analyst username
        reason: Optional reason for verdict
        
    Returns:
        {'status': 'success', 'message': str}
    """
    try:
        # Store feedback
        feedback = {
            'alert_id': request.alert_id,
            'model_prediction': request.model_prediction,
            'analyst_verdict': request.analyst_verdict,
            'analyst': request.analyst,
            'reason': request.reason,
            'submitted_at': datetime.now()
        }
        
        detector.db.fp_feedback.insert_one(feedback)
        
        # Update alert with verdict
        detector.db.alerts.update_one(
            {'alert_id': request.alert_id},
            {'$set': {
                'analyst_verdict': request.analyst_verdict,
                'analyst': request.analyst,
                'review_timestamp': datetime.now(),
                'review_reason': request.reason
            }}
        )
        
        # Track model accuracy
        is_correct = request.model_prediction == request.analyst_verdict
        
        return {
            'status': 'success',
            'message': 'Feedback submitted successfully',
            'model_correct': is_correct
        }
    
    except Exception as e:
        logger.error(f"Failed to submit feedback: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_stats():
    """
    Get FP detector statistics
    
    Returns:
        {
            'total_alerts_analyzed': int,
            'total_fps_detected': int,
            'total_feedback': int,
            'model_accuracy': float,
            'top_noisy_rules': list
        }
    """
    try:
        # Total alerts with FP analysis
        total_analyzed = detector.db.alerts.count_documents({
            'fp_analysis': {'$exists': True}
        })
        
        # Total FPs detected
        total_fps = detector.db.alerts.count_documents({
            'fp_analysis.fp_score': {'$gte': 0.7}
        })
        
        # Total feedback
        total_feedback = detector.db.fp_feedback.count_documents({})
        
        # Model accuracy (where we have feedback)
        if total_feedback > 0:
            correct = detector.db.fp_feedback.count_documents({
                'model_prediction': {'$exists': True},
                '$expr': {'$eq': ['$model_prediction', '$analyst_verdict']}
            })
            accuracy = correct / total_feedback
        else:
            accuracy = None
        
        # Top noisy rules
        top_noisy = list(detector.db.noisy_rules.find({}).sort('fp_rate', -1).limit(10))
        for rule in top_noisy:
            rule['_id'] = str(rule['_id'])
        
        return {
            'total_alerts_analyzed': total_analyzed,
            'total_fps_detected': total_fps,
            'total_feedback': total_feedback,
            'model_accuracy': accuracy,
            'top_noisy_rules': top_noisy
        }
    
    except Exception as e:
        logger.error(f"Failed to get stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5004)
