# The bootstrap PKCS#12 imported from Vault is a Docker-era leaf: CN=localhost
# with SANs for localhost and host.docker.internal only. Nothing could validate
# the engine by its real name, so nginx was pinned to `proxy-ssl-name: localhost`
# and every in-cluster caller reached PingFederate through its public URL
# instead -- which sent the RFC 8693 exchange, carrying the user's access token
# and the agent's JWT-SVID, out through the edge and back.
#
# This key names the engine as it is actually addressed: the public authorization
# server hostname, and the in-cluster Service in each form Kubernetes resolves.
# `localhost` stays in the list so the administrator port-forward and the
# transition from the bootstrap certificate keep working.
#
# The administrator console keeps the bootstrap key. It is reached only through a
# bounded loopback port-forward, so `localhost` is the correct identity for it and
# rotating it here would break the very channel Terraform is connected over.
resource "pingfederate_keypairs_ssl_server_key" "runtime" {
  count = length(var.runtime_server_dns_names) > 0 ? 1 : 0

  key_id                    = "wai-runtime-engine-tls"
  common_name               = var.runtime_server_dns_names[0]
  subject_alternative_names = var.runtime_server_dns_names
  organization              = "WAI"
  country                   = "AU"
  key_algorithm             = "RSA"
  key_size                  = 2048
  signature_algorithm       = "SHA256withRSA"
  valid_days                = 365
}

# Activation is deliberately a separate switch from generation. The runtime
# certificate cannot be swapped until every client already trusts the new leaf,
# so the reviewed sequence is: generate, publish the trust bundle, restart the
# clients, and only then activate.
resource "pingfederate_keypairs_ssl_server_settings" "runtime" {
  count = var.activate_runtime_server_certificate ? 1 : 0

  lifecycle {
    precondition {
      condition     = length(var.runtime_server_dns_names) > 0
      error_message = "Activating the runtime server certificate requires runtime_server_dns_names."
    }
  }

  runtime_server_cert_ref     = { id = pingfederate_keypairs_ssl_server_key.runtime[0].id }
  active_runtime_server_certs = [{ id = pingfederate_keypairs_ssl_server_key.runtime[0].id }]

  admin_console_cert_ref     = { id = var.admin_console_key_id }
  active_admin_console_certs = [{ id = var.admin_console_key_id }]
}
