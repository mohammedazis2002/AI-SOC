from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

# ── Locate project root (where .env exists)
BASE_DIR = Path(__file__).resolve().parent

while not (BASE_DIR / ".env").exists():
    if BASE_DIR.parent == BASE_DIR:
        raise RuntimeError(".env file not found")
    BASE_DIR = BASE_DIR.parent


class Settings(BaseSettings):
    app_name: str = "Ingestion Service"
    debug: bool = False
    port: int = 8000

    # Vault
    vault_addr: str = "http://127.0.0.1:8200"
    vault_role_id: str | None = None
    vault_secret_id: str | None = None
    vault_pki_path: str = "pki_int"
    vault_role_name: str = "fastapi-service"

    cert_dir: Path = Path("backend/services/mtls/app/security/certs")
    cert_common_name: str = "api.internal"
    cert_ttl: str = "720h"
    cert_renewal_threshold_days: int = 7

    # Wazuh certificate defaults
    wazuh_cert_common_name: str = "wazuh-manager.local"
    wazuh_cert_ttl: str = "720h"
    wazuh_allowed_domains: str = "wazuh.internal,wazuh-manager.local"

    require_client_cert: bool = True
    trusted_client_cn_pattern: str = "wazuh.*"

    # MongoDB
    mongo_uri: str | None = None

    # MongoDB (fallback config)
    mongodb_host: str = "mongodb"
    mongodb_port: int = 27017
    mongodb_database: str = "soar_db"
    mongodb_username: str | None = None
    mongodb_password: str | None = None
    mongodb_auth_source: str = "admin"

    # Build connection string dynamically
    @property
    def mongo_connection_string(self) -> str:
        #  If full URI provided → use it
        if self.mongo_uri:
            return self.mongo_uri

        # If auth is provided → build authenticated URI
        if self.mongodb_username and self.mongodb_password:
            return (
                f"mongodb://{self.mongodb_username}:{self.mongodb_password}"
                f"@{self.mongodb_host}:{self.mongodb_port}/"
                f"{self.mongodb_database}?authSource={self.mongodb_auth_source}"
            )

        # No auth → simple local connection
        return (
            f"mongodb://{self.mongodb_host}:{self.mongodb_port}/{self.mongodb_database}"
        )

    # Pydantic config
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        case_sensitive=False,
        extra="ignore",
    )


# Singleton instance
settings = Settings()
