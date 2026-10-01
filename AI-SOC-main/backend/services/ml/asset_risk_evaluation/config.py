"""
Configuration for Asset Risk Evaluation Service

Environment variables:
- MONGO_URI: MongoDB connection string
- MTLS_SERVICE_URL: mTLS service endpoint
- CORRELATION_ENGINE_URL: Correlation engine API endpoint
"""

import os
from typing import Optional

class Config:
    """Service configuration."""
    
    # MongoDB
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DATABASE: str = os.getenv("MONGO_DATABASE", "soar")
    
    # Service URLs
    MTLS_SERVICE_URL: Optional[str] = os.getenv("MTLS_SERVICE_URL")
    CORRELATION_ENGINE_URL: Optional[str] = os.getenv("CORRELATION_ENGINE_URL")
    
    # Service settings
    SERVICE_PORT: int = int(os.getenv("ASSET_RISK_PORT", "5005"))
    SERVICE_HOST: str = os.getenv("ASSET_RISK_HOST", "0.0.0.0")
    
    # Vulnerability cache settings
    VULN_CACHE_DAYS: int = int(os.getenv("VULN_CACHE_DAYS", "7"))
    
    # Incident history window
    INCIDENT_HISTORY_DAYS: int = int(os.getenv("INCIDENT_HISTORY_DAYS", "90"))
    
    # Risk factor weights (configurable)
    CRITICALITY_WEIGHT: float = float(os.getenv("CRITICALITY_WEIGHT", "0.25"))
    VULNERABILITY_WEIGHT: float = float(os.getenv("VULNERABILITY_WEIGHT", "0.30"))
    EXPOSURE_WEIGHT: float = float(os.getenv("EXPOSURE_WEIGHT", "0.20"))
    INCIDENT_WEIGHT: float = float(os.getenv("INCIDENT_WEIGHT", "0.15"))
    THREAT_INTEL_WEIGHT: float = float(os.getenv("THREAT_INTEL_WEIGHT", "0.10"))
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


config = Config()
