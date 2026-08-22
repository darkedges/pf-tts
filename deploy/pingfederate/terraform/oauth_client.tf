resource "pingfederate_oauth_client" "token_exchange" {
  lifecycle {
    # PingFederate never returns the plaintext secret. The provider therefore
    # reads encrypted_secret after creation and would otherwise plan a secret
    # rewrite on every refresh. Ignore only the two secret representations;
    # client_auth.type and every other client setting remain drift-managed.
    ignore_changes = [
      client_auth.secret,
      client_auth.encrypted_secret,
    ]
  }

  client_id   = var.token_exchange_client_id
  name        = "WAI Agent Token Exchange"
  description = "Confidential client used by WAI agents to perform RFC 8693 token exchange."

  client_auth = {
    type   = "SECRET"
    secret = var.token_exchange_client_secret
  }

  grant_types = [
    "TOKEN_EXCHANGE",
  ]

  restrict_scopes = true
  restricted_scopes = [
    var.transaction_scope,
  ]

  token_exchange_processor_policy_ref = {
    id = pingfederate_oauth_token_exchange_processor_policy.wai.policy_id
  }

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.transaction.manager_id
  }

  restrict_to_default_access_token_manager = true
}
