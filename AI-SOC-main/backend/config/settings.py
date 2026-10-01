"""
Configuration settings for SOAR Platform
Uses Pydantic Settings for type-safe configuration management
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application
    app_name: str = Field(default="SOAR Platform", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    debug: bool = Field(default=True, alias="DEBUG")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_workers: int = Field(default=4, alias="API_WORKERS")
    
    # MongoDB Configuration
    mongodb_host: str = Field(default="localhost", alias="MONGODB_HOST")
    mongodb_port: int = Field(default=27017, alias="MONGODB_PORT")
    mongodb_database: str = Field(default="soar_db", alias="MONGODB_DATABASE")
    mongodb_username: str = Field(default="soar_user", alias="MONGODB_USERNAME")
    mongodb_password: str = Field(default="change_this_password", alias="MONGODB_PASSWORD")
    mongodb_auth_source: str = Field(default="admin", alias="MONGODB_AUTH_SOURCE")
    
    # Redis Configuration
    redis_host: str = Field(default="localhost", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_password: Optional[str] = Field(default=None, alias="REDIS_PASSWORD")
    redis_db: int = Field(default=0, alias="REDIS_DB")
    redis_cache_db: int = Field(default=1, alias="REDIS_CACHE_DB")
    
    # Redis Streams Configuration
    redis_stream_incoming: str = Field(default="alerts:incoming", alias="REDIS_STREAM_INCOMING")
    redis_stream_dlq: str = Field(default="alerts:dlq", alias="REDIS_STREAM_DLQ")
    redis_stream_priority: str = Field(default="alerts:priority", alias="REDIS_STREAM_PRIORITY")
    redis_consumer_group: str = Field(default="soar-consumers", alias="REDIS_CONSUMER_GROUP")
    
    # Security
    secret_key: str = Field(default="change_this_secret_key", alias="SECRET_KEY")
    api_key_header: str = Field(default="X-API-Key", alias="API_KEY_HEADER")
    
    # LLM Configuration
    llm_service_url: str = Field(default="http://localhost:11434", alias="LLM_SERVICE_URL")
    llm_model_name: str = Field(default="mistral:latest", alias="LLM_MODEL_NAME")
    llm_timeout: int = Field(default=120, alias="LLM_TIMEOUT")
    ai_mapper_enabled: bool = Field(default=True, alias="AI_MAPPER_ENABLED")
    ai_confidence_threshold: float = Field(default=0.7, alias="AI_CONFIDENCE_THRESHOLD")
    
    # Vector Database (Qdrant)
    qdrant_host: str = Field(default="localhost", alias="QDRANT_HOST")
    qdrant_port: int = Field(default=6333, alias="QDRANT_PORT")
    qdrant_collection_name: str = Field(default="security_knowledge", alias="QDRANT_COLLECTION_NAME")
    
    # Monitoring
    prometheus_port: int = Field(default=9090, alias="PROMETHEUS_PORT")
    grafana_port: int = Field(default=3000, alias="GRAFANA_PORT")
    
    # Data Retention
    alert_retention_days: int = Field(default=90, alias="ALERT_RETENTION_DAYS")
    log_retention_days: int = Field(default=30, alias="LOG_RETENTION_DAYS")
    
    # Rate Limiting
    rate_limit_per_minute: int = Field(default=100, alias="RATE_LIMIT_PER_MINUTE")
    rate_limit_burst: int = Field(default=20, alias="RATE_LIMIT_BURST")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"  # Ignore extra fields from .env
    
    @property
    def mongodb_url(self) -> str:
        """Construct MongoDB connection URL"""
        return f"mongodb://{self.mongodb_username}:{self.mongodb_password}@{self.mongodb_host}:{self.mongodb_port}/{self.mongodb_database}?authSource={self.mongodb_auth_source}"
    
    @property
    def redis_url(self) -> str:
        """Construct Redis connection URL"""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"


# Global settings instance
settings = Settings()
