"""
Certificate Management Router
==============================
Endpoints for issuing and re-issuing Wazuh manager client certificates.
"""

from fastapi import APIRouter, HTTPException, status
import logging

from backend.services.mtls.app.schemas.certificates import (
    WazuhCertRequest,
    WazuhCertResponse,
    CertRevokeRequest,
    CertRevokeResponse,
    IssuedCertListResponse,
    IssuedCertListItem,
    parse_common_name_from_pem,
    WAZUH_ALLOWED_DOMAINS,
)
from backend.services.mtls.app.security.vault_client import vault_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/certificates", tags=["certificate-management"])


@router.post(
    "/wazuh",
    response_model=WazuhCertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a Wazuh manager client certificate",
    description=(
        "Issue a new client certificate for a Wazuh manager instance via Vault PKI. "
        "The common_name must be within the allowed Wazuh domains."
    ),
)
async def issue_wazuh_certificate(req: WazuhCertRequest):
    """Issue a new Wazuh manager client certificate from Vault PKI."""

    # Validate common_name against allowed domains
    cn = req.common_name
    is_allowed = any(
        cn == domain or cn.endswith(f".{domain}") for domain in WAZUH_ALLOWED_DOMAINS
    )
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Common name '{cn}' is not within allowed Wazuh domains: "
                f"{WAZUH_ALLOWED_DOMAINS}"
            ),
        )

    try:
        cert_data = vault_client.issue_wazuh_certificate(
            common_name=cn,
            ttl=req.ttl,
        )
        logger.info(f"Issued Wazuh certificate for CN={cn}, serial={cert_data['serial_number']}")
        return WazuhCertResponse(**cert_data)

    except Exception as e:
        logger.error(f"Failed to issue Wazuh certificate: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Certificate issuance failed: {str(e)}",
        )


@router.post(
    "/wazuh/renew",
    response_model=WazuhCertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Re-issue (renew) a Wazuh manager client certificate",
    description=(
        "Re-issue a client certificate for a Wazuh manager. Functionally identical "
        "to issuance but logged as a renewal for audit purposes."
    ),
)
async def renew_wazuh_certificate(req: WazuhCertRequest):
    """Re-issue a Wazuh manager client certificate (renewal)."""

    cn = req.common_name
    is_allowed = any(
        cn == domain or cn.endswith(f".{domain}") for domain in WAZUH_ALLOWED_DOMAINS
    )
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Common name '{cn}' is not within allowed Wazuh domains: "
                f"{WAZUH_ALLOWED_DOMAINS}"
            ),
        )

    try:
        cert_data = vault_client.issue_wazuh_certificate(
            common_name=cn,
            ttl=req.ttl,
        )
        logger.info(
            f"Renewed Wazuh certificate for CN={cn}, serial={cert_data['serial_number']}"
        )
        return WazuhCertResponse(**cert_data)

    except Exception as e:
        logger.error(f"Failed to renew Wazuh certificate: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Certificate renewal failed: {str(e)}",
        )


@router.post(
    "/revoke",
    response_model=CertRevokeResponse,
    summary="Revoke a certificate",
    description="Revoke a previously issued certificate by its serial number.",
)
async def revoke_certificate(req: CertRevokeRequest):
    """Revoke a certificate by serial number."""

    try:
        vault_client.revoke_certificate(req.serial_number)
        logger.info(f"Revoked certificate serial={req.serial_number}")
        return CertRevokeResponse(
            status="revoked",
            serial_number=req.serial_number,
        )

    except Exception as e:
        logger.error(f"Failed to revoke certificate: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Certificate revocation failed: {str(e)}",
        )


@router.get(
    "/wazuh/certs",
    response_model=IssuedCertListResponse,
    summary="List issued Wazuh certificates",
    description=(
        "Lists issued certificates from Vault PKI (pki_int/certs) and returns minimal metadata "
        "(serial, CN, revoked)."
    ),
)
async def list_wazuh_certificates():
    try:
        serials = vault_client.list_issued_cert_serials()

        items: list[IssuedCertListItem] = []
        for serial in serials:
            data = vault_client.read_certificate_by_serial(serial)
            pem = data.get("certificate")
            cn = parse_common_name_from_pem(pem)

            # Filter to Wazuh allowed domains if we can infer CN
            if cn:
                is_allowed = any(
                    cn == domain or cn.endswith(f".{domain}") for domain in WAZUH_ALLOWED_DOMAINS
                )
                if not is_allowed:
                    continue

            revoked = bool((data.get("revocation_time") or 0) > 0)
            items.append(
                IssuedCertListItem(
                    serial_number=serial,
                    common_name=cn,
                    revoked=revoked,
                    revocation_time_rfc3339=(data.get("revocation_time_rfc3339") or None),
                    certificate_pem=None,
                )
            )

        return IssuedCertListResponse(items=items)
    except Exception as e:
        logger.error(f"Failed to list issued Wazuh certs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Certificate list failed: {str(e)}",
        )
