path "pki_int/cert/ca" {
  capabilities = ["read"]
}

path "pki_int/issue/wazuh-manager" {
  capabilities = ["create", "update"]
}

path "pki_int/revoke" {
  capabilities = ["create", "update"]
}
