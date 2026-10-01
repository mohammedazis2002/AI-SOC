"""Proxy routes to the mTLS certificate management service (Vault PKI)."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.dependencies.auth import require_role_names

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mtls", tags=["mtls-certs"])


class CertIssueRequest(BaseModel):
    common_name: str = Field(..., min_length=1, max_length=200)
    ttl: str | None = Field(default=None, description="Vault-style TTL, e.g. 720h")


class CertRevokeRequest(BaseModel):
    serial_number: str = Field(..., min_length=1, max_length=200)


def _cert_api_base() -> str:
    return get_settings().mtls_cert_api_url.strip().rstrip("/")


def _detail_from_error_response(r: httpx.Response) -> str:
    raw = (r.text or "").strip()
    try:
        data = r.json()
        if isinstance(data, dict) and "detail" in data:
            d = data["detail"]
            if isinstance(d, str):
                return d[:8000]
            if isinstance(d, list):
                return str(d)[:8000]
            return str(d)[:8000]
    except ValueError:
        pass
    return (raw[:8000] if raw else f"Upstream HTTP {r.status_code}")


def _parse_success_json(r: httpx.Response) -> dict[str, Any]:
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=_detail_from_error_response(r))

    body = (r.content or b"").strip()
    if not body:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Certificate service returned an empty response. "
                "Check MTLS_CERT_API_URL, that the mTLS API container is running, "
                "and Vault/PKI is healthy."
            ),
        )

    try:
        data = r.json()
    except ValueError as e:
        logger.warning("mTLS proxy: non-JSON success body: %s", e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Certificate service returned non-JSON (Content-Type: "
                f"{r.headers.get('content-type', 'unknown')}). "
                f"Verify MTLS_CERT_API_URL points at the certificate API, not another service."
            ),
        ) from e

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Certificate service returned JSON that is not an object.",
        )
    return data


async def _post_json(path_suffix: str, json_body: dict[str, Any]) -> dict[str, Any]:
    base = _cert_api_base()
    if not base:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Certificate API is disabled (MTLS_CERT_API_URL is empty).",
        )
    url = f"{base}{path_suffix}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0, follow_redirects=True) as client:
            r = await client.post(url, json=json_body)
        return _parse_success_json(r)
    except HTTPException:
        raise
    except httpx.RequestError as e:
        logger.warning("mTLS proxy POST %s failed: %s", url, e)
        host_part = url.split("/")[2] if "://" in url else url
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Cannot reach certificate API ({host_part}). "
                f"If the web API runs on your host (not Docker), set MTLS_CERT_API_URL to a reachable URL "
                f"(e.g. https://127.0.0.1:8444/api/v1/certificates when compose publishes 8444→8443). "
                f"Error: {e}"
            ),
        ) from e


async def _get_json(path_suffix: str) -> dict[str, Any]:
    base = _cert_api_base()
    if not base:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Certificate API is disabled (MTLS_CERT_API_URL is empty).",
        )
    url = f"{base}{path_suffix}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0, follow_redirects=True) as client:
            r = await client.get(url)
        return _parse_success_json(r)
    except HTTPException:
        raise
    except httpx.RequestError as e:
        logger.warning("mTLS proxy GET %s failed: %s", url, e)
        host_part = url.split("/")[2] if "://" in url else url
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Cannot reach certificate API ({host_part}): {e}",
        ) from e


@router.post(
    "/certificates/issue",
    dependencies=[Depends(require_role_names({"Admin", "Engineer"}))],
)
async def issue_cert(body: CertIssueRequest) -> dict[str, Any]:
    return await _post_json("/wazuh", body.model_dump(exclude_none=True))


@router.post(
    "/certificates/renew",
    dependencies=[Depends(require_role_names({"Admin", "Engineer"}))],
)
async def renew_cert(body: CertIssueRequest) -> dict[str, Any]:
    return await _post_json("/wazuh/renew", body.model_dump(exclude_none=True))


@router.post(
    "/certificates/revoke",
    dependencies=[Depends(require_role_names({"Admin", "Engineer"}))],
)
async def revoke_cert(body: CertRevokeRequest) -> dict[str, Any]:
    return await _post_json("/revoke", body.model_dump())


@router.get(
    "/certificates",
    dependencies=[Depends(require_role_names({"Admin", "Engineer"}))],
)
async def list_certs() -> dict[str, Any]:
    return await _get_json("/wazuh/certs")
