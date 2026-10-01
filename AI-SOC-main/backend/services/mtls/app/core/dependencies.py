from fastapi import Depends, Request
from typing import Annotated

from backend.services.mtls.app.core.security import cert_authenticator
from backend.services.mtls.app.core.config import settings
from backend.services.mtls.app.security.vault_client import vault_client


async def verify_client_certificate(request: Request) -> dict:
    """Validate client certificates"""
    if not settings.require_client_cert:
        return {"common_name": "anonymous", "issuer": "mtls-disabled"}
    return cert_authenticator.validate_client_certificate(request)


CertificateInfo = Annotated[dict, Depends(verify_client_certificate)]


def get_vault_client():
    """Get Vault client instance"""
    return vault_client
