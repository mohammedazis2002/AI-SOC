# Token policy for the mTLS / certificate API (AppRole: fastapi-service).
# Must allow issuing Wazuh client certs and managing the service's own server cert.

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
