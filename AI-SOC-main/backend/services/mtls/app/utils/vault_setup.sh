#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Resolve paths relative to this script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../security/certs"

# Ensure certs directory exists
mkdir -p "${CERTS_DIR}"

echo -e "${BLUE} Setting up Vault PKI...${NC}"

# Require VAULT_ADDR and VAULT_TOKEN to be set in the environment.
# Export them before running this script, e.g.:
#   export VAULT_ADDR='http://127.0.0.1:8200'
#   export VAULT_TOKEN='hvs.xxxxx'   (from vault server -dev output)
export VAULT_ADDR="${VAULT_ADDR:?'VAULT_ADDR must be set (e.g. http://127.0.0.1:8200)'}"
export VAULT_TOKEN="${VAULT_TOKEN:?'VAULT_TOKEN must be set (copy root token from vault server -dev output)'}"

# Check if Vault is accessible
if ! vault status >/dev/null 2>&1; then
  echo -e "${RED} Cannot connect to Vault. Make sure:${NC}"
  echo "   1. Vault is running: vault server -dev"
  echo "   2. VAULT_ADDR is set: export VAULT_ADDR='http://127.0.0.1:8200'"
  echo "   3. VAULT_TOKEN is set: export VAULT_TOKEN='hvs.xxxxx'"
  exit 1
fi

echo -e "${GREEN}✓ Connected to Vault${NC}"

# Step 1: Enable PKI engines
echo -e "${BLUE} Enabling PKI secrets engines...${NC}"
vault secrets enable pki 2>/dev/null || echo "  pki already enabled"
vault secrets tune -max-lease-ttl=87600h pki

vault secrets enable -path=pki_int pki 2>/dev/null || echo "  pki_int already enabled"
vault secrets tune -max-lease-ttl=43800h pki_int

echo -e "${GREEN}✓ PKI engines enabled${NC}"

# Step 2: Generate Root CA
echo -e "${BLUE} Generating Root CA...${NC}"
vault write -field=certificate pki/root/generate/internal \
  common_name="Secure Intelligence Root CA" \
  issuer_name="root-2024" \
  ttl=87600h >"${CERTS_DIR}/root_ca.crt"

vault write pki/config/urls \
  issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
  crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

echo -e "${GREEN}✓ Root CA created (saved to root_ca.crt)${NC}"

# Step 3: Generate Intermediate CA
echo -e "${BLUE} Generating Intermediate CA...${NC}"
vault write -field=csr pki_int/intermediate/generate/internal \
  common_name="Secure Intelligence Intermediate CA" \
  issuer_name="intermediate-ca" >"${CERTS_DIR}/pki_intermediate.csr"

vault write -field=certificate pki/root/sign-intermediate \
  issuer_ref="root-2024" \
  csr=@"${CERTS_DIR}/pki_intermediate.csr" \
  format=pem_bundle \
  ttl="43800h" >"${CERTS_DIR}/intermediate.cert.pem"

vault write pki_int/intermediate/set-signed \
  certificate=@"${CERTS_DIR}/intermediate.cert.pem"

vault write pki_int/config/urls \
  issuing_certificates="$VAULT_ADDR/v1/pki_int/ca" \
  crl_distribution_points="$VAULT_ADDR/v1/pki_int/crl"

echo -e "${GREEN}✓ Intermediate CA created${NC}"

# Step 4: Create PKI Roles
echo -e "${BLUE} Creating PKI roles...${NC}"

# Update Wazuh role to allow any name in the allowed domains
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

# Update FastAPI role
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

echo -e "${GREEN}✓ PKI roles created${NC}"

# Step 5: Create Policies
echo -e "${BLUE} Creating Vault policies...${NC}"

# Wazuh Manager policy
cat >/tmp/wazuh-policy.hcl <<'EOF'
path "pki_int/cert/ca" {
  capabilities = ["read"]
}

path "pki_int/issue/wazuh-manager" {
  capabilities = ["create", "update"]
}

path "pki_int/revoke" {
  capabilities = ["create", "update"]
}
EOF

vault policy write wazuh-manager /tmp/wazuh-policy.hcl

# FastAPI service policy (includes wazuh-manager issuance for the API endpoint)
# Keep in sync with infra/docker/vault/policies/fastapi-service.hcl
cat >/tmp/fastapi-policy.hcl <<'EOF'
path "pki_int/cert/ca" {
  capabilities = ["read"]
}

path "pki_int/issue/fastapi-service" {
  capabilities = ["create", "update"]
}

path "pki_int/issue/wazuh-manager" {
  capabilities = ["create", "update"]
}

path "pki_int/revoke" {
  capabilities = ["create", "update"]
}

path "pki_int/ca_chain" {
  capabilities = ["read"]
}

path "pki_int/certs" {
  capabilities = ["list"]
}

path "pki_int/cert/*" {
  capabilities = ["read"]
}
EOF

vault policy write fastapi-service /tmp/fastapi-policy.hcl

echo -e "${GREEN}✓ Policies created${NC}"

# Step 6: Setup AppRole Authentication
echo -e "${BLUE}🎭 Setting up AppRole authentication...${NC}"

vault auth enable approle 2>/dev/null || echo "  approle already enabled"

# Create AppRole for Wazuh
vault write auth/approle/role/wazuh-manager \
  token_policies="wazuh-manager" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0

# Create AppRole for FastAPI
vault write auth/approle/role/fastapi-service \
  token_policies="fastapi-service" \
  token_ttl=1h \
  token_max_ttl=4h

echo -e "${GREEN}✓ AppRoles created${NC}"

# Step 7: Get credentials
echo -e "${BLUE} Retrieving AppRole credentials...${NC}"
echo ""
echo -e "${GREEN}=== FastAPI Service Credentials ===${NC}"
echo "Role ID:"
vault read -field=role_id auth/approle/role/fastapi-service/role-id
echo ""
echo "Secret ID:"
vault write -field=secret_id -f auth/approle/role/fastapi-service/secret-id
echo ""

echo -e "${GREEN}=== Wazuh Manager Credentials ===${NC}"
echo "Role ID:"
vault read -field=role_id auth/approle/role/wazuh-manager/role-id
echo ""
echo "Secret ID:"
vault write -field=secret_id -f auth/approle/role/wazuh-manager/secret-id
echo ""

echo -e "${GREEN} Vault PKI setup complete!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Update services/ingestion/.env with FastAPI credentials"
echo "2. Save Wazuh credentials for later use"
echo "3. Start your ingestion service"

# Cleanup temp files
rm -f /tmp/wazuh-policy.hcl /tmp/fastapi-policy.hcl
