#!/bin/bash

# Require Vault environment variables to be set before running
export VAULT_ADDR="${VAULT_ADDR:?'VAULT_ADDR must be set (e.g. http://127.0.0.1:8200)'}"
export VAULT_TOKEN="${VAULT_TOKEN:?'VAULT_TOKEN must be set'}"

# Generate Wazuh certificate
vault write -format=json pki_int/issue/wazuh-manager \
  common_name="wazuh-manager.local" \
  ttl="720h" >wazuh_cert_response.json

cat wazuh_cert_response.json | jq -r '.data.certificate' >wazuh_cert.pem
cat wazuh_cert_response.json | jq -r '.data.private_key' >wazuh_key.pem
cat wazuh_cert_response.json | jq -r '.data.ca_chain[]' >wazuh_ca_chain.pem

# Generate FastAPI certificate
vault write -format=json pki_int/issue/fastapi-service \
  common_name="api.internal" \
  ttl="720h" >fastapi_cert_response.json

cat fastapi_cert_response.json | jq -r '.data.certificate' >fastapi_cert.pem
cat fastapi_cert_response.json | jq -r '.data.private_key' >fastapi_key.pem
cat fastapi_cert_response.json | jq -r '.data.ca_chain[]' >fastapi_ca_chain.pem

# Verify files are not empty
ls -lh *.pem
