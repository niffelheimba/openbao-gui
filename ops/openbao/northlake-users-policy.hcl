path "pki_user_mtls/sign/northlake-users" {
  capabilities = ["update"]
}

path "pki_user_mtls/revoke" {
  capabilities = ["update"]
}

path "pki_user_mtls/cert/*" {
  capabilities = ["read"]
}

path "pki_user_mtls/ca" {
  capabilities = ["read"]
}

path "pki_user_mtls/crl" {
  capabilities = ["read"]
}
