resource "pingfederate_keypairs_ssl_server_key" "local_runtime" {
  key_id                    = "wai-local-runtime-tls"
  common_name               = "host.docker.internal"
  organization              = "WAI local development"
  country                   = "AU"
  key_algorithm             = "RSA"
  key_size                  = 2048
  signature_algorithm       = "SHA256withRSA"
  valid_days                = 365
  subject_alternative_names = ["host.docker.internal", "localhost", "wai-pingfederate-13-1"]
}

resource "pingfederate_keypairs_ssl_server_settings" "local_runtime" {
  admin_console_cert_ref = {
    id = pingfederate_keypairs_ssl_server_key.local_runtime.id
  }
  runtime_server_cert_ref = {
    id = pingfederate_keypairs_ssl_server_key.local_runtime.id
  }
  active_admin_console_certs = [{
    id = pingfederate_keypairs_ssl_server_key.local_runtime.id
  }]
  active_runtime_server_certs = [{
    id = pingfederate_keypairs_ssl_server_key.local_runtime.id
  }]
}
