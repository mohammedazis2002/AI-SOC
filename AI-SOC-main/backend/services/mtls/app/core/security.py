from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, padding
from cryptography.x509.oid import NameOID
from fastapi import HTTPException, status, Request
from pathlib import Path
import logging
import re
from urllib.parse import unquote_plus

from backend.services.mtls.app.core.config import settings

logger = logging.getLogger(__name__)


class CertificateAuthenticator:
    """Validates client certificates for mTLS authentication"""

    def __init__(self):
        self.ca_cert_path = settings.cert_dir / "ca.crt"
        self.intermediate_cert_path = settings.cert_dir / "intermediate.cert.pem"
        self._trusted_issuers: list[x509.Certificate] = []
        self.trusted_cn_pattern = re.compile(settings.trusted_client_cn_pattern)
        self._load_ca_cert()

    def _load_ca_cert(self):
        """Load CA / intermediate certificates used for validation."""
        try:
            self._trusted_issuers = []
            if self.ca_cert_path.exists():
                with open(self.ca_cert_path, "rb") as f:
                    self._trusted_issuers.append(
                        x509.load_pem_x509_certificate(f.read(), default_backend())
                    )
                logger.info("Loaded root CA certificate")
            else:
                logger.warning(f"CA certificate not found at {self.ca_cert_path}")

            # Optional intermediate (Vault often returns a chain)
            if self.intermediate_cert_path.exists():
                with open(self.intermediate_cert_path, "rb") as f:
                    self._trusted_issuers.append(
                        x509.load_pem_x509_certificate(f.read(), default_backend())
                    )
                logger.info("Loaded intermediate certificate")
        except Exception as e:
            logger.warning(f"Failed to load CA certificate: {e}")
            logger.warning("Certificate authentication will fail if enabled.")
            self._trusted_issuers = []

    def _normalize_client_cert_header(self, raw: str) -> str:
        """
        Proxies commonly send an escaped/URL-encoded PEM in a header.
        Examples:
          - nginx: $ssl_client_escaped_cert  (URL-escaped, no newlines)
          - some proxies: spaces instead of newlines
        """
        raw = raw.strip()
        # URL decode (nginx escaped cert)
        raw = unquote_plus(raw)
        if "-----BEGIN CERTIFICATE-----" in raw:
            return raw
        # Fallback: treat as base64 body with spaces/newlines stripped
        body = raw.replace(" ", "\n").strip()
        return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"

    def _verify_signature_against_trust(self, client_cert: x509.Certificate) -> None:
        if not self._trusted_issuers:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="mTLS CA certificates not loaded on server",
            )
        last_err: Exception | None = None
        for issuer_cert in self._trusted_issuers:
            pub = issuer_cert.public_key()
            try:
                if isinstance(pub, rsa.RSAPublicKey):
                    pub.verify(
                        client_cert.signature,
                        client_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        client_cert.signature_hash_algorithm,
                    )
                elif isinstance(pub, ec.EllipticCurvePublicKey):
                    pub.verify(
                        client_cert.signature,
                        client_cert.tbs_certificate_bytes,
                        ec.ECDSA(client_cert.signature_hash_algorithm),
                    )
                elif isinstance(pub, dsa.DSAPublicKey):
                    pub.verify(
                        client_cert.signature,
                        client_cert.tbs_certificate_bytes,
                        client_cert.signature_hash_algorithm,
                    )
                else:
                    raise ValueError(f"Unsupported issuer public key type: {type(pub)}")
                return
            except Exception as e:
                last_err = e
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Client certificate not signed by trusted CA: {last_err}",
        )

    def validate_client_certificate(self, request: Request) -> dict:
        """
        Validate client certificate from request

        Returns:
            dict: Certificate information if valid

        Raises:
            HTTPException: If certificate is invalid or missing
        """

        # In production with proper TLS termination, the certificate
        # will be in request headers added by reverse proxy (nginx, traefik)
        # For now, we'll implement basic validation

        # Get client cert from header (set by TLS-terminating proxy)
        client_cert_pem = request.headers.get("X-SSL-Client-Cert")

        if not client_cert_pem:
            logger.warning("Client certificate not provided in request")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client certificate required",
            )

        try:
            # Parse PEM certificate (header might be URL-encoded / escaped)
            client_cert_pem = self._normalize_client_cert_header(client_cert_pem)
            client_cert = x509.load_pem_x509_certificate(
                client_cert_pem.encode(), default_backend()
            )

            # Validate certificate
            self._validate_certificate(client_cert)

            # Extract certificate details
            cert_info = self._extract_cert_info(client_cert)

            logger.info(f"Authenticated client: {cert_info['common_name']}")

            return cert_info

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Certificate validation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid client certificate: {str(e)}",
            )

    def _validate_certificate(self, client_cert: x509.Certificate):
        """Perform certificate validation checks"""
        from datetime import datetime

        # Check validity period
        now = datetime.utcnow()

        if now < client_cert.not_valid_before:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Certificate not yet valid",
            )

        if now > client_cert.not_valid_after:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Certificate has expired",
            )

        # Cryptographically verify the leaf certificate signature against trusted issuer cert(s).
        # This is stronger than a subject/issuer string comparison.
        self._verify_signature_against_trust(client_cert)

        # Check Common Name matches trusted pattern
        subject = client_cert.subject
        cn_attr = subject.get_attributes_for_oid(NameOID.COMMON_NAME)

        if not cn_attr:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Certificate missing Common Name",
            )

        common_name = cn_attr[0].value

        if not self.trusted_cn_pattern.match(common_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Certificate CN '{common_name}' not authorized",
            )

    def _extract_cert_info(self, client_cert: x509.Certificate) -> dict:
        """Extract useful information from certificate"""
        subject = client_cert.subject

        def get_attr(oid):
            attrs = subject.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else None

        return {
            "common_name": get_attr(NameOID.COMMON_NAME),
            "organization": get_attr(NameOID.ORGANIZATION_NAME),
            "organizational_unit": get_attr(NameOID.ORGANIZATIONAL_UNIT_NAME),
            "country": get_attr(NameOID.COUNTRY_NAME),
            "serial_number": client_cert.serial_number,
            "not_valid_before": client_cert.not_valid_before.isoformat(),
            "not_valid_after": client_cert.not_valid_after.isoformat(),
        }


# Global authenticator instance
cert_authenticator = CertificateAuthenticator()
