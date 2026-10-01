"""Ingestion Service - Secure Intelligence Platform"""

from fastapi import FastAPI
from contextlib import asynccontextmanager
import logging
from motor.motor_asyncio import AsyncIOMotorClient

from dotenv import load_dotenv

load_dotenv()

from backend.services.mtls.app.core.config import settings
from backend.services.mtls.app.core.logging import configure_logging
from backend.services.mtls.app.security.vault_client import vault_client
from backend.services.mtls.app.api.api import api_router

__version__ = "1.0.0"

configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Ingestion Service...")

    # Vault Init
    try:
        vault_client.authenticate()
        vault_client.initialize_certificates()
        logger.info("✓ Vault integration initialized")
        logger.info("✓ Certificates ready")
    except Exception as e:
        logger.warning(f"Vault init failed: {e}")
        logger.warning("Continuing in potentially insecure mode (Local Dev)")

    # MongoDB Init
    try:
        mongo_uri = settings.mongo_connection_string

        app.mongodb_client = AsyncIOMotorClient(mongo_uri)
        app.database = app.mongodb_client[settings.mongodb_database]

        logger.info(f"✓ MongoDB connected → {settings.mongodb_database}")
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")
        app.mongodb_client = None
        app.database = None

    logger.info("Service started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Ingestion Service...")

    if getattr(app, "mongodb_client", None):
        app.mongodb_client.close()
        logger.info("✓ MongoDB connection closed")


def create_app() -> FastAPI:
    """Application factory"""
    app = FastAPI(
        title="Secure Intelligence - Ingestion Service",
        description="Microservice for ingesting security alerts with mTLS authentication",
        version=__version__,
        lifespan=lifespan,
    )

    app.include_router(api_router)

    @app.get("/")
    async def root():
        return {"service": "ingestion", "status": "running", "version": __version__}

    return app


app = create_app()
