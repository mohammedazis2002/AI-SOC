from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic_settings import BaseSettings, SettingsConfigDict

# Monorepo: .../web_app/backend/app/core/config.py → parents[4] is AI-SOC root.
# Docker image: /app/app/core/config.py has only parents[0..3]; parents[4] raises IndexError — use parents[2] (= WORKDIR /app).
_cfg = Path(__file__).resolve()
try:
    _REPO_ENV = _cfg.parents[4] / '.env'
except IndexError:
    _REPO_ENV = _cfg.parents[2] / '.env'


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(_REPO_ENV, '.env'),
        env_file_encoding='utf-8',
        extra='ignore',
    )

    # Preferred split settings
    mongodb_host: str = 'localhost'
    mongodb_port: int = 27017
    mongodb_database: str = 'soar_db'
    mongodb_username: str = 'root'
    mongodb_password: str = 'strongpassword123'
    mongodb_auth_source: str = 'admin'

    # Optional full URI override
    mongo_uri: str | None = None

    jwt_secret: str = 'change-me-in-production'
    jwt_algorithm: str = 'HS256'
    access_token_expire_minutes: int = 60 * 24
    app_name: str = 'Cybolt Auth API'

    # Proxied to mTLS certificate API (Vault PKI). Docker stack: https://api:8443/...
    # Host dev (API on laptop): use https://127.0.0.1:8444/api/v1/certificates if compose maps 8444→8443.
    mtls_cert_api_url: str = 'https://api:8443/api/v1/certificates'

    @property
    def resolved_mongo_uri(self) -> str:
        if self.mongo_uri:
            return self.mongo_uri

        user = quote_plus(self.mongodb_username)
        pwd = quote_plus(self.mongodb_password)
        return (
            f'mongodb://{user}:{pwd}'
            f'@{self.mongodb_host}:{self.mongodb_port}/{self.mongodb_database}'
            f'?authSource={self.mongodb_auth_source}'
        )

    @property
    def mongo_db_name(self) -> str:
        return self.mongodb_database


@lru_cache
def get_settings() -> Settings:
    return Settings()
