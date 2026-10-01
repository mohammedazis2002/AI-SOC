#!/bin/sh
# One-shot: install Vault CLI + bash, then run repo vault_setup.sh against compose Vault.
# Mount repo at /work. Skip if pki_int is already mounted (idempotent guard).
set -eu

export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
if [ -z "${VAULT_TOKEN:-}" ]; then
  echo "run-pki-setup.sh: VAULT_TOKEN is not set" >&2
  exit 1
fi

apk add --no-cache bash curl unzip ca-certificates >/dev/null
update-ca-certificates >/dev/null 2>&1 || true

# Prefer Alpine vault package (fast mirrors). Fall back to HashiCorp CDN if the package is missing.
if command -v vault >/dev/null 2>&1; then
  echo "run-pki-setup.sh: using vault in PATH ($(command -v vault))"
elif apk add --no-cache vault 2>/dev/null && command -v vault >/dev/null 2>&1; then
  echo "run-pki-setup.sh: installed Vault CLI via apk."
else
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) VARCH=amd64 ;;
    aarch64) VARCH=arm64 ;;
    *) echo "run-pki-setup.sh: unsupported arch $ARCH" >&2; exit 1 ;;
  esac

  V_VER=1.15.6
  URL="https://releases.hashicorp.com/vault/${V_VER}/vault_${V_VER}_linux_${VARCH}.zip"
  echo "run-pki-setup.sh: apk vault unavailable — downloading ${V_VER} (${VARCH}) from releases.hashicorp.com"
  echo "  (progress bar below — can take 1–3+ minutes on slow networks; do not interrupt)"
  rm -f /tmp/vault.zip
  curl -fSL --progress-bar --connect-timeout 30 --retry 5 --retry-delay 3 --retry-connrefused \
    -o /tmp/vault.zip "$URL" || {
    echo "run-pki-setup.sh: download failed (network?). Retry: docker compose --profile setup run --rm vault-pki-bootstrap" >&2
    exit 1
  }
  unzip -oq /tmp/vault.zip -d /usr/local/bin
  chmod +x /usr/local/bin/vault
  echo "run-pki-setup.sh: Vault CLI installed from zip."
fi

if ! vault status >/dev/null 2>&1; then
  echo "run-pki-setup.sh: cannot reach Vault at $VAULT_ADDR" >&2
  exit 1
fi

LIST_JSON=$(vault secrets list -format=json 2>&1) || {
  echo "run-pki-setup.sh: vault secrets list failed (wrong VAULT_TOKEN?):" >&2
  echo "$LIST_JSON" >&2
  exit 1
}

if echo "$LIST_JSON" | grep -q '"pki_int/"'; then
  echo "run-pki-setup.sh: pki_int already mounted — skipping full PKI bootstrap."
  echo "  Run: docker compose run --rm vault-init"
  exit 0
fi

echo "run-pki-setup.sh: running vault_setup.sh (first-time PKI)..."
cd /work
exec bash /work/backend/services/mtls/app/utils/vault_setup.sh
