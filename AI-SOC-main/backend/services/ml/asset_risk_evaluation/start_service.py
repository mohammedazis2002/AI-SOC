"""
Asset Risk Evaluation Service - Standalone Startup Script

Run this script to start the service:
    python start_service.py

Or from project root:
    python backend/services/ml/asset_risk_evaluation/start_service.py
"""

import sys
import os
from pathlib import Path

# Add backend directory to path for imports
backend_dir = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

# Now import and run the service
from services.ml.asset_risk_evaluation.service import app

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("🚀 Starting Asset Risk Evaluation Service")
    print("=" * 60)
    print(f"📍 Service URL: http://0.0.0.0:5005")
    print(f"📚 API Docs: http://localhost:5005/docs")
    print(f"💾 MongoDB: {os.getenv('MONGO_URI', 'mongodb://localhost:27017')}")
    print("=" * 60)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5005,
        log_level="info"
    )
