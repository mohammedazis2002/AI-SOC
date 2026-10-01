"""
Root Cause Analyzer Service - FastAPI
Model 3: Multi-Label Random Forest for root cause identification

Port: 5003
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import logging
import numpy as np
from pathlib import Path
import sys

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from services.ml.root_cause_analysis.root_cause_analyzer import analyzer, RootCauseAnalyzer
from services.ml.root_cause_analysis.root_cause_feature_extractor import feature_extractor
from services.ml.context_building.context_builder import ContextBuilder
from config.database import get_database

# Initialize context builder
context_builder = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Root Cause Analyzer Service",
    description="Model 3: Identifies WHY attacks succeeded using Multi-Label Random Forest",
    version="1.0.0"
)


# Request/Response Models
class AlertAnalysisRequest(BaseModel):
    alert: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None
    
    class Config:
        schema_extra = {
            "example": {
                "alert": {
                    "finding": {
                        "title": "Brute Force Attack",
                        "types": ["T1110"],
                        "desc": "Multiple failed password attempts"
                    },
                    "severity_id": 4,
                    "mitre_enrichment": {
                        "dominant_tactic": "credential-access"
                    }
                },
                "context": {
                    "user_mfa_enabled": False,
                    "asset_criticality": 0.8
                }
            }
        }


class RootCauseResponse(BaseModel):
    alert_id: str
    num_root_causes: int
    root_causes: List[Dict[str, Any]]
    dominant_cause: Optional[Dict[str, Any]]
    remediation: List[str]
    temporal_analysis: Dict[str, Any]


class AutoLabelRequest(BaseModel):
    alert: Dict[str, Any]


class AutoLabelResponse(BaseModel):
    suggestions: Dict[str, Dict[str, Any]]
    needs_review: bool
    confidence_summary: Dict[str, float]


class ContextBuildRequest(BaseModel):
    alert: Dict[str, Any]
    lookback_days: int = 7  # How many days of history to fetch
    
    class Config:
        schema_extra = {
            "example": {
                "alert": {
                    "actor": {"user": {"name": "jdoe"}},
                    "dst_endpoint": {"hostname": "server01"}
                },
                "lookback_days": 7
            }
        }


@app.on_event("startup")
async def load_model():
    """Load trained model on startup"""
    global context_builder
    try:
        analyzer.load("models/root_cause_analyzer.pkl")
        logger.info("✅ Root Cause Analyzer model loaded successfully")
    except FileNotFoundError:
        logger.warning("⚠️  Model not found. Train model first with train_root_cause_analyzer.py")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
    
    # Initialize context builder
    try:
        context_builder = ContextBuilder()
        logger.info("✅ Context Builder initialized")
    except Exception as e:
        logger.error(f"Failed to initialize context builder: {e}")


@app.get("/")
async def root():
    """Service info"""
    return {
        "service": "Root Cause Analyzer",
        "model": "Multi-Label Random Forest",
        "version": "1.0.0",
        "status": "running",
        "categories": len(RootCauseAnalyzer.CATEGORIES),
        "features": 30,
        "trained": analyzer.trained
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy" if analyzer.trained else "untrained",
        "model_loaded": analyzer.trained,
        "categories": RootCauseAnalyzer.CATEGORIES,
        "feature_count": 30
    }


@app.post("/analyze", response_model=RootCauseResponse)
async def analyze_root_cause(request: AlertAnalysisRequest):
    """
    Analyze root causes for an alert
    
    Context is OPTIONAL - if not provided, it will be built automatically
    by querying MongoDB for historical data.
    
    Returns: Root causes with confidence + remediation steps
    """
    if not analyzer.trained:
        raise HTTPException(status_code=503, detail="Model not trained yet")
    
    try:
        # AUTO-BUILD CONTEXT if not provided
        if not request.context and context_builder:
            logger.info("No context provided - building automatically from MongoDB...")
            try:
                request.context = context_builder.build_context(
                    request.alert,
                    lookback_days=7
                )
                logger.info(f"✅ Context auto-built: {len(request.context.get('recent_alerts', []))} recent alerts")
            except Exception as e:
                logger.warning(f"Failed to auto-build context: {e}. Proceeding without context.")
                request.context = {}
        elif not request.context:
            logger.warning("Context not provided and ContextBuilder not available. Using empty context.")
            request.context = {}
        
        # Extract features
        db = get_database()
        feature_extractor.db = db
        
        features = feature_extractor.extract(request.alert, request.context or {})
        
        # Analyze
        analysis = analyzer.analyze_alert(
            features,
            alert_context=request.context or {}
        )
        
        # Add temporal analysis summary
        temporal_summary = {
            "has_temporal_data": bool(request.context),
            "tactic": request.context.get('mitre_tactic', 'unknown') if request.context else 'unknown',
            "origin_cause": None
        }
        
        # Identify origin cause (highest priority)
        for cause in analysis['root_causes']:
            if cause.get('priority') == 'primary':
                temporal_summary['origin_cause'] = cause['cause']
                break
        
        # If no primary, use highest confidence
        if not temporal_summary['origin_cause'] and analysis['root_causes']:
            temporal_summary['origin_cause'] = analysis['root_causes'][0]['cause']
        
        return {
            "alert_id": request.alert.get('alert_id', 'unknown'),
            "num_root_causes": analysis['num_root_causes'],
            "root_causes": analysis['root_causes'],
            "dominant_cause": analysis['dominant_cause'],
            "remediation": analysis['remediation'],
            "temporal_analysis": temporal_summary
        }
    
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auto-label", response_model=AutoLabelResponse)
async def auto_label_alert(request: AutoLabelRequest):
    """
    Auto-suggest root cause labels for an alert (semi-supervised labeling)
    
    Analyst can then confirm/correct suggestions
    """
    try:
        suggestions = analyzer.auto_suggest_labels(request.alert)
        
        # Check if needs review
        confident_suggestions = {
            cat: sug for cat, sug in suggestions.items()
            if sug['confidence'] >= 0.75
        }
        
        needs_review = len(confident_suggestions) == 0
        
        # Confidence summary
        confidence_summary = {
            'max_confidence': max([s['confidence'] for s in suggestions.values()]) if suggestions else 0.0,
            'avg_confidence': np.mean([s['confidence'] for s in suggestions.values()]) if suggestions else 0.0,
            'num_confident': len(confident_suggestions)
        }
        
        return {
            "suggestions": suggestions,
            "needs_review": needs_review,
            "confidence_summary": confidence_summary
        }
    
    except Exception as e:
        logger.error(f"Auto-labeling failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/build-context")
async def build_context_for_alert(request: ContextBuildRequest):
    """
    Build context for an alert by querying historical data
    
    This constructs the context parameter needed for accurate root cause analysis.
    It includes:
    - Recent alerts from the same user/asset
    - User profile (risk score, account age, privileges)
    - Asset profile (criticality, patch status)
    
    Returns: Complete context object ready for /analyze endpoint
    """
    if not context_builder:
        raise HTTPException(
            status_code=503, 
            detail="Context builder not initialized. Check database connection."
        )
    
    try:
        context = context_builder.build_context(
            request.alert, 
            lookback_days=request.lookback_days
        )
        
        return {
            "context": context,
            "metadata": {
                "recent_alerts_count": len(context.get("recent_alerts", [])),
                "user_identified": context.get("user_profile") is not None,
                "asset_identified": context.get("asset_profile") is not None,
                "lookback_days": request.lookback_days
            }
        }
    
    except Exception as e:
        logger.error(f"Context building failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/categories")
async def get_categories():
    """Get all 14 root cause categories"""
    return {
        "categories": RootCauseAnalyzer.CATEGORIES,
        "count": len(RootCauseAnalyzer.CATEGORIES),
        "descriptions": {
            'weak_credentials': "Weak/default/reused passwords",
            'unpatched_vulnerability': "Missing security patches (CVEs)",
            'misconfiguration': "Network/cloud/API misconfigurations",
            'lack_of_mfa': "No multi-factor authentication",
            'insufficient_monitoring': "Logging/detection gaps",
            'social_engineering': "Phishing, pretexting",
            'insider_threat': "Malicious/negligent insider",
            'supply_chain': "Third-party compromise",
            'zero_day_exploit': "Unknown vulnerability",
            'inadequate_segmentation': "Poor network isolation",
            'excessive_privileges': "Over-permissioned accounts",
            'outdated_software': "End-of-life software",
            'defense_evasion': "LOLBIN abuse, obfuscation",
            'api_security_gap': "Insecure APIs, broken auth"
        }
    }


@app.get("/stats")
async def get_statistics():
    """Get model statistics"""
    if not analyzer.trained:
        return {"trained": False, "message": "Model not trained yet"}
    
    return {
        "trained": True,
        "training_stats": analyzer.train_stats,
        "feature_names": analyzer.feature_names if analyzer.feature_names else RootCauseFeatureExtractor.FEATURE_NAMES
    }


@app.get("/metrics")
async def get_metrics():
    """Get service metrics"""
    db = get_database()
    
    # Count labeled samples
    total_labeled = db.root_cause_training.count_documents({})
    analyst_labeled = db.root_cause_training.count_documents({'labeling_method': 'analyst_reviewed'})
    auto_labeled = db.root_cause_training.count_documents({'labeling_method': 'auto_suggested'})
    
    return {
        "model_trained": analyzer.trained,
        "training_data": {
            "total_samples": total_labeled,
            "analyst_reviewed": analyst_labeled,
            "auto_suggested": auto_labeled,
            "auto_confirmed": total_labeled - analyst_labeled - auto_labeled
        },
        "categories": len(RootCauseAnalyzer.CATEGORIES),
        "features": 30
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5006)
