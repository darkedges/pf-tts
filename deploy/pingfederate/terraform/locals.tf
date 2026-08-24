locals {
  policy_id = "wai-agent-transaction"

  transaction_token_profile      = var.enable_transaction_tokens_inner_profile ? "ietf-txn-token-v11" : "legacy-wai-jwt"
  effective_transaction_audience = var.enable_transaction_tokens_inner_profile ? var.trust_domain : var.transaction_audience
  effective_transaction_scope    = var.enable_transaction_tokens_inner_profile ? var.transaction_tokens_scope : var.transaction_scope

  transaction_attributes = toset([
    "user_id",
    "agent_id",
    "agent_instance_id",
    "workload_id",
    "transaction_id",
    "transaction_purpose",
    "scope",
  ])

  transaction_atm_attributes = toset([
    "sub",
    "agent_id",
    "agent_instance_id",
    "workload_id",
    "transaction_id",
    "transaction_purpose",
    "scope",
    "aud",
  ])

  # Keep token-type identifiers centralized. If the deployed PingFederate
  # release reports a different JWT actor token-type identifier, change it
  # here and in the Go client together.
  subject_token_type = "urn:ietf:params:oauth:token-type:access_token"
  actor_token_type   = "urn:ietf:params:oauth:token-type:jwt"
}
