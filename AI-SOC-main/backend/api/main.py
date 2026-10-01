"""
SOAR Platform - Main FastAPI Application
"""

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
import os
import logging
from contextlib import asynccontextmanager

from api.routes import ingestion
from api.routes import incidents
from config.database import db_manager
from services.ingestion.queue_manager import queue_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    logger.info("🚀 Starting SOAR Platform...")
    
    try:
        # Connect to MongoDB
        try:
            await db_manager.connect()
            logger.info("✅ MongoDB initialized")
        except Exception as e:
            logger.warning(f"⚠️  MongoDB unavailable (degraded mode): {e}")
            logger.warning("   → Set MONGODB_HOST=localhost in .env for local dev")
        
        # Connect to Redis
        try:
            await queue_manager.connect()
            logger.info("✅ Redis queue initialized")
        except Exception as e:
            logger.warning(f"⚠️  Redis unavailable (degraded mode): {e}")
        
        logger.info("🎉 SOAR Platform started (some services may be degraded)")
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down SOAR Platform...")
    
    try:
        await db_manager.disconnect()
        await queue_manager.disconnect()
        logger.info("✅ Cleanup completed")
    except Exception as e:
        logger.error(f"❌ Shutdown error: {e}")


# Create FastAPI app
app = FastAPI(
    title="SOAR Platform API",
    description="Security Orchestration, Automation, and Response Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# Include Routers
app.include_router(ingestion.router)
app.include_router(incidents.router)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Health check endpoint for load balancer and monitoring"""
    
    # Check database health
    db_health = await db_manager.health_check()
    
    # Check queue health
    queue_health = await queue_manager.health_check()
    
    # Overall health
    is_healthy = (
        db_health.get("status") == "healthy" and
        queue_health.get("status") == "healthy"
    )
    
    return JSONResponse(
        status_code=status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "healthy" if is_healthy else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "soar-api",
            "environment": os.getenv("APP_ENV", "development"),
            "components": {
                "database": db_health,
                "queue": queue_health
            }
        }
    )

# Root endpoint
@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    """Root endpoint"""
    return {
        "message": "SOAR Platform API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/api/docs"
    }

# Metrics endpoint (placeholder for Prometheus)
@app.get("/metrics", status_code=status.HTTP_200_OK)
async def metrics():
    """Prometheus metrics endpoint"""
    # Get queue stats
    queue_stats = await queue_manager.get_queue_stats()
    
    return {
        "message": "Metrics endpoint - Prometheus integration pending",
        "queue_stats": queue_stats
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
