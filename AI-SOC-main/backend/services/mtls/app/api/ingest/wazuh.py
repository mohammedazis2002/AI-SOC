"""
Wazuh Ingestion Router
======================
Thin HTTP layer only. All business logic lives in wazuh_service.py.
"""

from fastapi import APIRouter, Request, status, HTTPException
import logging

from backend.services.mtls.app.schemas.ingest.wazuh import (
    WazuhAlert,
    WazuhAlertResponse,
)
from backend.services.mtls.app.core.dependencies import CertificateInfo
from backend.services.mtls.app.services.ingest.wazuh_service import process_wazuh_alert

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["wazuh-ingestion"])


@router.post(
    "/wazuh",
    response_model=WazuhAlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Receive Wazuh SIEM alerts",
    description="Ingest alerts from Wazuh Manager. Requires valid mTLS client certificate.",
)
async def ingest_wazuh_alert(
    request: Request,
    alert: WazuhAlert,
    cert_info: CertificateInfo,
):
    """Receive, normalise, and store a Wazuh alert."""
    logger.info(
        f"Received alert from {cert_info['common_name']}: "
        f"Rule {alert.rule.id} (Level {alert.rule.level})"
    )

    # Get DB handle from app state
    db = getattr(request.app, "database", None)
    if db is None:
        logger.error("MongoDB not available — cannot process alert")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )

    # Delegate to service layer
    try:
        result = await process_wazuh_alert(alert, cert_info, db)
    except Exception as e:
        logger.error(
            f"Unexpected error processing alert {alert.id}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process alert",
        )

    # ── Build response ────────────────────────────────────────────────────────
    return WazuhAlertResponse(
        status="success" if result.success else "failed",
        message=result.message,
        alert_id=result.alert_id or alert.id,
    )


@router.get(
    "/health",
    summary="Health check",
    description="Service health check (no authentication required)",
)
async def health_check():
    return {"status": "healthy", "service": "ingestion"}
