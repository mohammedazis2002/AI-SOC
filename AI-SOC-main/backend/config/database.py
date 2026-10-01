"""
MongoDB Database Manager for SOAR Platform
Handles async connections and collection access
"""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional
import logging
from backend.config.settings import settings

logger = logging.getLogger(__name__)


class DatabaseManager:
    """MongoDB connection manager with async support"""
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        self._connected = False
    
    async def connect(self):
        """Establish connection to MongoDB"""
        try:
            logger.info(f"Connecting to MongoDB at {settings.mongodb_host}:{settings.mongodb_port}")
            
            self.client = AsyncIOMotorClient(
                settings.mongodb_url,
                serverSelectionTimeoutMS=5000,
                maxPoolSize=50,
                minPoolSize=10
            )
            
            # Test connection
            await self.client.admin.command('ping')
            
            self.db = self.client[settings.mongodb_database]
            self._connected = True
            
            logger.info("✅ MongoDB connected successfully")
            
        except Exception as e:
            logger.error(f"❌ MongoDB connection failed: {e}")
            raise
    
    async def disconnect(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self._connected = False
            logger.info("MongoDB connection closed")
    
    async def health_check(self) -> dict:
        """Check MongoDB health"""
        try:
            if not self._connected:
                return {"status": "disconnected"}
            
            # Ping database
            await self.client.admin.command('ping')
            
            # Get server info
            server_info = await self.client.server_info()
            
            return {
                "status": "healthy",
                "version": server_info.get("version"),
                "database": settings.mongodb_database
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }
    
    # Collection accessors
    @property
    def alerts_raw(self):
        """Raw alerts collection"""
        return self.db.alerts_raw
    
    @property
    def alerts_processed(self):
        """Processed alerts collection (ULF format)"""
        return self.db.alerts_processed
    
    @property
    def actions_taken(self):
        """Automated actions collection"""
        return self.db.actions_taken
    
    @property
    def model_predictions(self):
        """ML model predictions collection"""
        return self.db.model_predictions
    
    @property
    def feedback_data(self):
        """Analyst feedback collection"""
        return self.db.feedback_data
    
    @property
    def correlation_groups(self):
        """Attack chain correlation groups"""
        return self.db.correlation_groups
    
    @property
    def user_profiles(self):
        """User behavior analytics profiles"""
        return self.db.user_profiles


# Global database manager instance
db_manager = DatabaseManager()


# Dependency for FastAPI
async def get_database() -> DatabaseManager:
    """FastAPI dependency to get database manager"""
    if not db_manager._connected:
        await db_manager.connect()
    return db_manager
