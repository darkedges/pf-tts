resource "pingfederate_keypairs_signing_key" "transaction" {
  key_id              = "wai-transaction-signing"
  common_name         = "WAI Transaction Token Signing"
  organization        = "WAI Local Lab"
  country             = "AU"
  key_algorithm       = "RSA"
  key_size            = 2048
  signature_algorithm = "SHA256withRSA"
  valid_days          = 365
}

resource "pingfederate_keypairs_oauth_openid_connect" "transaction" {
  static_jwks_enabled = true

  rsa_active_cert_ref = {
    id = pingfederate_keypairs_signing_key.transaction.key_id
  }
  rsa_active_key_id         = pingfederate_keypairs_signing_key.transaction.key_id
  rsa_publish_x5c_parameter = true
  publish_dynamic_key_x5cs  = false
}
