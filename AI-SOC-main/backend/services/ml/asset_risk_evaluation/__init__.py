"""
Asset Risk Evaluation Package

Model 5: Comprehensive OCSF-based asset risk scoring

Components:
- Automated compliance detection (PCI/PII/PHI)
- Asset type & industry detection
- Enhanced risk calculator (5 factors, 100+ variables)
- MongoDB persistence
- FastAPI service
"""

__version__ = "2.0.0"

# Core components
from .enums import ComprehensiveAssetType, Industry, Criticality, DataClassification
from .data_models import (
    AssetProfile,
    VulnerabilityData,
    ComprehensiveExposureData,
    IncidentHistoryData,
    ThoroughThreatIntelData,
    RiskCalculationResult,
    RiskLevel
)

# Detectors
from .compliance_detector import AutomatedComplianceDetector
from .asset_detectors import AssetTypeDetector, IndustryDetector

# Risk calculator
from .enhanced_risk_calculator import EnhancedAssetRiskCalculator

# MongoDB
try:
    from .mongodb_integration import MongoDBIntegration
except ImportError:
    MongoDBIntegration = None

__all__ = [
    # Enums
    "ComprehensiveAssetType",
    "Industry",
    "Criticality",
    "DataClassification",
    "RiskLevel",
    
    # Data models
    "AssetProfile",
    "VulnerabilityData",
    "ComprehensiveExposureData",
    "IncidentHistoryData",
    "ThoroughThreatIntelData",
    "RiskCalculationResult",
    
    # Detectors
    "AutomatedComplianceDetector",
    "AssetTypeDetector",
    "IndustryDetector",
    
    # Risk calculator
    "EnhancedAssetRiskCalculator",
    
    # MongoDB
    "MongoDBIntegration",
]
