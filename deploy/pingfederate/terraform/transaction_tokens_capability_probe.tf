resource "pingfederate_oauth_client" "transaction_tokens_trust_domain_probe" {
  count = var.enable_transaction_tokens_capability_probe || var.enable_transaction_tokens_inner_profile ? 1 : 0

  client_id   = var.trust_domain
  name        = "Isolated Transaction Tokens Trust Domain Probe"
  description = "Created only in random clean-bootstrap state to distinguish trust-domain audience resolution from requested token-type support."

  client_auth = {
    type   = "SECRET"
    secret = var.mcp_gateway_client_secret
  }

  grant_types = [
    "ACCESS_TOKEN_VALIDATION",
  ]

  restrict_scopes = true
  restricted_scopes = [
    local.effective_transaction_scope,
  ]

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.transaction.manager_id
  }

  restrict_to_default_access_token_manager = true
}
