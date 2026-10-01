"""
Asset Risk Evaluation Service - Main Service Layer

FastAPI service for OCSF-based asset risk evaluation.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional
import logging
import os
from datetime import datetime

# Local imports
from .compliance_detector import AutomatedComplianceDetector
from .asset_detectors import AssetTypeDetector, IndustryDetector
from .data_models import (
    AssetProfile, VulnerabilityData, ComprehensiveExposureData,
    IncidentHistoryData, ThoroughThreatIntelData
)
from .risk_calculator import EnhancedAssetRiskCalculator
from .mongodb_integration import MongoDBIntegration
from .enums import ComprehensiveAssetType, Industry, Criticality, DataClassification

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Asset Risk Evaluation Service",
    description="Model 5: OCSF-based asset risk scoring with comprehensive factors",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
compliance_detector = AutomatedComplianceDetector()
asset_type_detector = AssetTypeDetector()
industry_detector = IndustryDetector()
risk_calculator = EnhancedAssetRiskCalculator()

# MongoDB integration (with fallback)
try:
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    mongo_db = MongoDBIntegration(mongo_uri, database_name="soar")
    logger.info("✅ MongoDB integration enabled")
except Exception as e:
    logger.warning(f"⚠️ MongoDB not available: {e}. Running without persistence.")
    mongo_db = None


# =================================================================
# Request/Response Models
# =================================================================

class RiskAssessmentRequest(BaseModel):
    """Risk assessment request."""
    alert: Dict[str, Any]
    include_recommendations: bool = True


class RiskAssessmentResponse(BaseModel):
    """Risk assessment response."""
    asset_id: str
    risk_score: float
    risk_level: str
    factor_scores: Dict[str, float]
    factor_contributions: Dict[str, float]
    asset_profile: Dict[str, Any]
    recommendations: list = []
    top_risk_factors: list = []
    calculated_at: str


# =================================================================
# API Endpoints
# =================================================================

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "service": "Asset Risk Evaluation",
        "version": "2.0.0",
        "status": "running",
        "mongodb_connected": mongo_db is not None
    }


@app.post("/assess_risk", response_model=RiskAssessmentResponse)
async def assess_risk(request: RiskAssessmentRequest):
    """
    Assess risk for an asset based on OCSF alert.
    
    Args:
        request: RiskAssessmentRequest with OCSF alert
    
    Returns:
        RiskAssessmentResponse with comprehensive risk score
    """
    try:
        alert = request.alert
        
        # === Step 1: Extract asset information ===
        device = alert.get("device", {})
        asset_id = device.get("hostname") or device.get("ip") or "unknown"
        hostname = device.get("hostname", asset_id)
        ip_address = device.get("ip")
        
        logger.info(f"Assessing risk for asset: {asset_id}")
        
        # === Step 2: Run automated detectors ===
        
        # Compliance detection
        mtls_cert = None  # TODO: Get from mTLS service
        compliance_flags = compliance_detector.detect_compliance(alert, hostname, mtls_cert)
        
        # Asset type detection
        os_info = device.get("os", {})
        asset_type = asset_type_detector.detect(hostname, os_info, alert)
        
        # Industry detection
        domain = alert.get("dst_endpoint", {}).get("domain", "")
        industry = industry_detector.detect(hostname, domain)
        
        # === Step 3: Build asset profile ===
        profile = AssetProfile(
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            asset_type=asset_type,
            industry=industry,
            criticality=Criticality.HIGH,  # Default, can be refined
            has_pci_data=compliance_flags["has_pci_data"],
            has_pii=compliance_flags["has_pii"],
            has_phi=compliance_flags["has_phi"],
            os_name=os_info.get("name"),
            os_version=os_info.get("version"),
            environment="production"  # Default
        )
        
        # === Step 4: Get vulnerability data ===
        # Priority: Alert → MongoDB cache → NVD (not implemented here for brevity)
        vuln_data = VulnerabilityData()  # Placeholder
        
        # === Step 5: Build exposure data ===
        exposure_data = _extract_exposure_from_alert(alert)
        
        # === Step 6: Get incident history (from MongoDB) ===
        incidents = IncidentHistoryData()
        if mongo_db:
            incidents = mongo_db.get_incident_history(asset_id, days=90)
        
        # === Step 7: Get threat intelligence ===
        threat_intel = ThoroughThreatIntelData()  # Placeholder for Phase 2
        
        # === Step 8: Calculate risk ===
        result = risk_calculator.calculate_risk(
            profile=profile,
            vulnerabilities=vuln_data,
            exposure=exposure_data,
            incidents=incidents,
            threat_intel=threat_intel
        )
        
        # === Step 9: Save to MongoDB ===
        if mongo_db:
            mongo_db.save_asset_profile(
                profile=profile,
                risk_score=result.total_risk_score,
                risk_level=result.risk_level.value
            )
        
        # === Step 10: Return response ===
        return RiskAssessmentResponse(
            asset_id=asset_id,
            risk_score=result.total_risk_score,
            risk_level=result.risk_level.value,
            factor_scores=result.to_dict()["factor_scores"],
            factor_contributions=result.to_dict()["factor_contributions"],
            asset_profile={
                "asset_type": asset_type.value,
                "industry": industry.value,
                "compliance": compliance_flags
            },
            recommendations=result.recommendations if request.include_recommendations else [],
            top_risk_factors=result.top_risk_factors,
            calculated_at=result.calculated_at.isoformat()
        )
        
    except Exception as e:
        logger.error(f"Risk assessment failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def _extract_exposure_from_alert(alert: Dict) -> ComprehensiveExposureData:
    """
    Extract exposure data from OCSF alert.
    
    This is a simplified version. Full implementation would:
    - Query mTLS service for encryption data
    - Check EDR/SIEM coverage
    - Query backup systems
    - etc.
    """
    exposure = ComprehensiveExposureData()
    
    # Network zone detection
    dst_endpoint = alert.get("dst_endpoint", {})
    if "internet" in str(dst_endpoint).lower():
        exposure.internet_facing = True
        exposure.internal_only = False
    
    # Port extraction
    if dst_endpoint.get("port"):
        exposure.open_ports = [dst_endpoint["port"]]
    
    # Privilege detection
    actor = alert.get("actor", {})
    if actor.get("privileges"):
        exposure.has_privileged_access = True
    
    return exposure


# =================================================================
# Additional Endpoints
# =================================================================

@app.get("/asset/{asset_id}/profile")
async def get_asset_profile(asset_id: str):
    """Get asset profile from MongoDB."""
    if not mongo_db:
        raise HTTPException(status_code=503, detail="MongoDB not available")
    
    profile = mongo_db.get_asset_profile(asset_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return profile


@app.get("/asset/{asset_id}/incidents")
async def get_asset_incidents(asset_id: str, days: int = 90):
    """Get incident history for asset."""
    if not mongo_db:
        raise HTTPException(status_code=503, detail="MongoDB not available")
    
    incidents = mongo_db.get_incident_history(asset_id, days)
    return incidents

@app.get("/health")
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "components": {
            "compliance_detector": "ok",
            "asset_detector": "ok",
            "risk_calculator": "ok",
            "mongodb": "ok" if mongo_db else "disabled"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

