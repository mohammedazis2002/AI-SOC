"""
Certificate Management Schemas
===============================
Request/response models for Wazuh manager certificate issuance.
"""


from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend


WAZUH_ALLOWED_DOMAINS = ["wazuh.internal", "wazuh-manager.local"]
_CN_PATTERN = re.compile(r"CN=([^,]+)")


class WazuhCertRequest(BaseModel):
    """Request body for issuing a Wazuh manager client certificate"""

    common_name: str = Field(
        default="wazuh-manager.local",
        description="Common Name for the certificate. Must be within allowed Wazuh domains.",
        examples=["wazuh-manager.local", "wazuh.internal"],
    )
    ttl: str = Field(
        default="720h",
        description="Certificate time-to-live (e.g. '720h', '30d')",
    )


class WazuhCertResponse(BaseModel):
    """Response containing the issued certificate bundle"""

    certificate: str = Field(..., description="PEM-encoded client certificate")
    private_key: str = Field(..., description="PEM-encoded private key")
    ca_chain: List[str] = Field(
        default_factory=list, description="PEM-encoded CA chain certificates"
    )
    serial_number: str = Field(..., description="Certificate serial number")
    expiration: str = Field(..., description="Certificate expiration timestamp")

    @field_validator("expiration", mode="before")
    @classmethod
    def coerce_expiration(cls, v):
        """Vault returns expiration as a Unix timestamp (int). Convert to ISO string."""
        if isinstance(v, (int, float)):
            return datetime.utcfromtimestamp(v).isoformat() + "Z"
        return str(v)

    issued_at: datetime = Field(
        default_factory=datetime.utcnow, description="Timestamp of issuance"
    )


class CertRevokeRequest(BaseModel):
    """Request body for revoking a certificate"""

    serial_number: str = Field(..., description="Serial number of the certificate to revoke")


class CertRevokeResponse(BaseModel):
    """Response after revoking a certificate"""

    status: str = Field(..., description="Revocation status")
    serial_number: str = Field(..., description="Revoked certificate serial number")
    revoked_at: datetime = Field(
        default_factory=datetime.utcnow, description="Revocation timestamp"
    )


class IssuedCertListItem(BaseModel):
    """Minimal listing view for a Vault-issued cert."""

    serial_number: str = Field(..., description="Certificate serial number")
    common_name: str | None = Field(default=None, description="Parsed CN from the certificate subject")
    revoked: bool = Field(default=False, description="True if Vault reports revocation_time > 0")
    revocation_time_rfc3339: str | None = Field(default=None, description="RFC3339 revocation time if revoked")
    certificate_pem: str | None = Field(default=None, description="PEM certificate (optional)")


class IssuedCertListResponse(BaseModel):
    items: List[IssuedCertListItem]


def parse_common_name_from_pem(pem: str | None) -> str | None:
    """Parse CN from a PEM certificate string (best-effort)."""
    if not pem:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
        attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if attrs:
            return str(attrs[0].value)
    except Exception:
        # Fallback: regex if cryptography parse fails
        m = _CN_PATTERN.search(pem.replace("\n", " "))
        return m.group(1).strip() if m else None
    return None
