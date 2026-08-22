resource "pingfederate_oauth_client" "mcp_gateway" {
  lifecycle {
    ignore_changes = [
      client_auth.secret,
      client_auth.encrypted_secret,
    ]
  }

  client_id   = var.exchange_target_audience
  name        = "WAI MCP Gateway Resource Server"
  description = "Confidential resource-server client selected as the RFC 8693 audience."

  client_auth = {
    type   = "SECRET"
    secret = var.mcp_gateway_client_secret
  }

  grant_types = ["ACCESS_TOKEN_VALIDATION"]

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.transaction.manager_id
  }

  restrict_to_default_access_token_manager = true
  validate_using_all_eligible_atms         = false
}
