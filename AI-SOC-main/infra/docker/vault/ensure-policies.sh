#!/bin/sh
# 1) Ensure pki_int roles exist (wazuh-manager, fastapi-service) so Vault exposes
#    POST .../pki_int/issue/<role> (fixes "route entry not found").
# 2) Write ACL policies and refresh AppRole token_policies when roles already exist.
# Run as a one-shot container after Vault is healthy (docker-compose service vault-init).
set -eu

export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
if [ -z "${VAULT_TOKEN:-}" ]; then
  echo "ensure-policies.sh: VAULT_TOKEN is not set" >&2
  exit 1
fi

echo "ensure-policies.sh: VAULT_ADDR=$VAULT_ADDR"

# --- PKI roles (registers POST .../pki_int/issue/<role>; must match utils/vault_setup.sh) ---
LIST_JSON=$(vault secrets list -format=json 2>&1) || {
  echo "ensure-policies.sh: ERROR: vault secrets list failed (check VAULT_TOKEN matches .env VAULT_DEV_ROOT_TOKEN):" >&2
  echo "$LIST_JSON" >&2
  exit 1
}
if ! echo "$LIST_JSON" | grep -q '"pki_int/"'; then
  echo "ensure-policies.sh: ERROR: secrets engine pki_int is not mounted." >&2
  echo "  First-time PKI (no host Vault CLI needed):" >&2
  echo "    docker compose --profile setup run --rm vault-pki-bootstrap" >&2
  echo "  Then:" >&2
  echo "    docker compose run --rm vault-init && docker compose restart api" >&2
  echo "  Or from host with vault CLI: VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root> bash backend/services/mtls/app/utils/vault_setup.sh" >&2
  exit 1
fi

echo "ensure-policies.sh: ensuring pki_int roles wazuh-manager + fastapi-service exist..."
vault write pki_int/roles/wazuh-manager \
  allowed_domains="wazuh.internal,wazuh-manager.local" \
  allow_subdomains=true \
  allow_bare_domains=true \
  max_ttl="720h" \
  key_bits=2048 \
  key_type="rsa" \
  allow_any_name=false \
  client_flag=true \
  server_flag=false \
  require_cn=true

vault write pki_int/roles/fastapi-service \
  allowed_domains="api.internal,fastapi.local,localhost" \
  allow_subdomains=true \
  allow_bare_domains=true \
  max_ttl="720h" \
  key_bits=2048 \
  key_type="rsa" \
  server_flag=true \
  client_flag=false \
  require_cn=true

# --- ACL policies ---
vault policy write fastapi-service /policies/fastapi-service.hcl
vault policy write wazuh-manager /policies/wazuh-manager.hcl

vault auth enable approle 2>/dev/null || true

# Only update AppRoles if they already exist (vault_setup creates them). Avoids generating a new
# role_id on a fresh Vault before the user has run vault_setup and copied credentials to .env.
# Must match utils/vault_setup.sh — do NOT set bind_secret_id=true here; it breaks Secret IDs
# issued by vault_setup (login fails with "invalid role or secret ID").
if vault read auth/approle/role/fastapi-service >/dev/null 2>&1; then
  vault write auth/approle/role/fastapi-service \
    token_policies=fastapi-service \
    token_ttl=1h \
    token_max_ttl=4h
  echo "ensure-policies.sh: fastapi-service AppRole token_policies refreshed."
else
  echo "ensure-policies.sh: WARNING: auth/approle/role/fastapi-service not found — run backend/services/mtls/app/utils/vault_setup.sh once with root token, then restart."
fi

if vault read auth/approle/role/wazuh-manager >/dev/null 2>&1; then
  vault write auth/approle/role/wazuh-manager \
    token_policies=wazuh-manager \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0
fi

echo "ensure-policies.sh: done."
