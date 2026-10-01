import hvac
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import UTC, datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from backend.services.mtls.app.core.config import settings

logger = logging.getLogger(__name__)


class VaultPKIClient:
    """Handles Vault PKI operations for certificate management"""

    def __init__(self):
        self.vault_addr = settings.vault_addr
        self.role_id = settings.vault_role_id
        self.secret_id = settings.vault_secret_id
        self.cert_dir = settings.cert_dir
        self.client: Optional[hvac.Client] = None
        self.cert_dir.mkdir(parents=True, exist_ok=True)

    def authenticate(self) -> bool:
        """Authenticate with Vault using AppRole"""
        try:
            role_id = (self.role_id or "").strip()
            secret_id = (self.secret_id or "").strip()
            if not role_id or not secret_id:
                raise ValueError("vault_role_id and vault_secret_id must be set in environment / .env")

            self.client = hvac.Client(url=self.vault_addr)
            auth_response = self.client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id,
            )
            logger.info("Successfully authenticated with Vault")
            return True
        except Exception as e:
            logger.error(f"Failed to authenticate with Vault: {e}")
            raise

    def _ensure_authenticated(self):
        """Ensure we have a valid Vault token"""
        if not self.client or not self.client.is_authenticated():
            self.authenticate()

    def issue_server_certificate(self) -> bool:
        """Issue server certificate for this service"""
        try:
            self._ensure_authenticated()
            logger.info(f"Requesting certificate for {settings.cert_common_name}")

            response = self.client.write(
                f"{settings.vault_pki_path}/issue/{settings.vault_role_name}",
                common_name=settings.cert_common_name,
                ttl=settings.cert_ttl,
                alt_names="localhost",
                ip_sans="127.0.0.1",
            )

            cert_data = response["data"]
            cert_file = self.cert_dir / "server.crt"
            key_file = self.cert_dir / "server.key"
            ca_file = self.cert_dir / "ca.crt"

            with open(cert_file, "w") as f:
                f.write(cert_data["certificate"])
                f.write("\n")
                if "ca_chain" in cert_data and cert_data["ca_chain"]:
                    f.write("\n".join(cert_data["ca_chain"]))

            with open(key_file, "w") as f:
                f.write(cert_data["private_key"])

            with open(ca_file, "w") as f:
                f.write(cert_data["issuing_ca"])

            key_file.chmod(0o600)
            cert_file.chmod(0o644)
            ca_file.chmod(0o644)

            logger.info(f"Server certificate issued successfully")
            logger.info(f"  Certificate: {cert_file}")
            logger.info(f"  Private Key: {key_file}")
            logger.info(f"  CA Cert: {ca_file}")

            return True

        except Exception as e:
            logger.error(f"Failed to issue server certificate: {e}")
            raise

    def get_ca_certificate(self) -> str:
        """Retrieve CA certificate for validating client certificates"""
        try:
            self._ensure_authenticated()
            response = self.client.read(f"{settings.vault_pki_path}/cert/ca")
            return response["data"]["certificate"]
        except Exception as e:
            logger.error(f"Failed to get CA certificate: {e}")
            raise

    def should_renew_certificate(self) -> bool:
        """Check if server certificate needs renewal"""
        cert_path = self.cert_dir / "server.crt"

        if not cert_path.exists():
            logger.info("Certificate file not found, needs issuance")
            return True

        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            now = datetime.now(UTC)
            try:
                not_after = cert.not_valid_after_utc
            except AttributeError:
                na = cert.not_valid_after
                not_after = na.replace(tzinfo=UTC) if na.tzinfo is None else na

            days_until_expiry = (not_after - now).days
            should_renew = days_until_expiry < settings.cert_renewal_threshold_days

            if should_renew:
                logger.info(
                    f"Certificate expires in {days_until_expiry} days, "
                    f"threshold is {settings.cert_renewal_threshold_days} days. Renewal needed."
                )
            else:
                logger.info(f"Certificate valid for {days_until_expiry} more days")

            return should_renew

        except Exception as e:
            logger.error(f"Error checking certificate expiry: {e}")
            return True

    def issue_wazuh_certificate(
        self, common_name: str = "wazuh-manager.local", ttl: str = "720h"
    ) -> dict:
        """Issue a client certificate for a Wazuh manager via Vault PKI.

        Args:
            common_name: CN for the certificate (must be within allowed Wazuh domains).
            ttl: Certificate time-to-live.

        Returns:
            dict with certificate, private_key, ca_chain, serial_number, expiration.
        """
        try:
            self._ensure_authenticated()
            logger.info(f"Issuing Wazuh client certificate for CN={common_name}")

            response = self.client.write(
                f"{settings.vault_pki_path}/issue/wazuh-manager",
                common_name=common_name,
                ttl=ttl,
            )

            cert_data = response["data"]

            return {
                "certificate": cert_data["certificate"],
                "private_key": cert_data["private_key"],
                "ca_chain": cert_data.get("ca_chain", []),
                "serial_number": cert_data["serial_number"],
                "expiration": cert_data.get("expiration", ""),
            }

        except Exception as e:
            logger.error(f"Failed to issue Wazuh certificate: {e}")
            raise

    def revoke_certificate(self, serial_number: str) -> bool:
        """Revoke a certificate by serial number.

        Args:
            serial_number: The serial number of the certificate to revoke.

        Returns:
            True if revocation was successful.
        """
        try:
            self._ensure_authenticated()
            logger.info(f"Revoking certificate serial={serial_number}")

            self.client.write(
                f"{settings.vault_pki_path}/revoke",
                serial_number=serial_number,
            )

            logger.info(f"Certificate {serial_number} revoked successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke certificate {serial_number}: {e}")
            raise

    def list_issued_cert_serials(self) -> List[str]:
        """List issued certificate serial numbers from Vault PKI."""
        try:
            self._ensure_authenticated()
            # HVAC exposes LIST via `.list()`
            resp = self.client.list(f"{settings.vault_pki_path}/certs")
            keys = (resp or {}).get("data", {}).get("keys", []) or []
            # Vault returns serials like "aa:bb:..."
            return [str(k) for k in keys]
        except Exception as e:
            logger.error(f"Failed to list issued cert serials: {e}")
            raise

    def read_certificate_by_serial(self, serial_number: str) -> Dict[str, Any]:
        """Read a certificate (PEM + revocation info) from Vault by serial."""
        try:
            self._ensure_authenticated()
            resp = self.client.read(f"{settings.vault_pki_path}/cert/{serial_number}")
            return (resp or {}).get("data", {}) or {}
        except Exception as e:
            logger.error(f"Failed to read cert serial={serial_number}: {e}")
            raise

    def initialize_certificates(self):
        """Initialize or renew certificates on startup"""
        try:
            if self.should_renew_certificate():
                logger.info("Initializing/renewing server certificate...")
                self.issue_server_certificate()
            else:
                logger.info("Existing certificate is valid")

            ca_path = self.cert_dir / "ca.crt"
            if not ca_path.exists():
                logger.info("Fetching CA certificate...")
                ca_cert = self.get_ca_certificate()
                with open(ca_path, "w") as f:
                    f.write(ca_cert)

        except Exception as e:
            logger.error(f"Certificate initialization failed: {e}")
            raise


vault_client = VaultPKIClient()
