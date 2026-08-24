output "token_exchange_policy_id" {
  value = pingfederate_oauth_token_exchange_processor_policy.wai.policy_id
}

output "token_exchange_client_id" {
  value = pingfederate_oauth_client.token_exchange.client_id
}

output "lab_user_client_id" {
  value = pingfederate_oauth_client.lab_user.client_id
}

output "browser_client_id" {
  value = pingfederate_oauth_client.browser.client_id
}

output "browser_redirect_uri" {
  value = var.browser_redirect_uri
}

output "transaction_access_token_manager_id" {
  value = pingfederate_oauth_access_token_manager.transaction.manager_id
}

output "actor_audience" {
  value = var.actor_audience
}

output "transaction_audience" {
  value = local.effective_transaction_audience
}

output "transaction_jwks_url" {
  value = "${var.pf_base_url}/pf/JWKS"
}

output "local_tls_certificate_id" {
  description = "PingFederate-managed local-development TLS certificate identifier."
  value       = pingfederate_keypairs_ssl_server_key.local_runtime.id
}

output "exchange_target_audience" {
  value = pingfederate_oauth_client.mcp_gateway.client_id
}

output "spire_agent_binding" {
  value = var.agent_bindings
}
