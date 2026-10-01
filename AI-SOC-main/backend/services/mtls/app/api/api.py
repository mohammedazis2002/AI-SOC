from fastapi import APIRouter
from backend.services.mtls.app.api.ingest import wazuh
from backend.services.mtls.app.api import certificates

api_router = APIRouter()

api_router.include_router(wazuh.router)
api_router.include_router(certificates.router)
