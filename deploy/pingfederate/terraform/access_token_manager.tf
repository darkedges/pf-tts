resource "pingfederate_oauth_access_token_manager" "transaction" {
  lifecycle {
    precondition {
      condition = alltrue([
        for required in ["Agent Bindings", "Transaction Purpose"] :
        contains([for field in var.transaction_atm_configuration_fields : field.name], required)
      ])
      error_message = "The transaction ATM requires exact trusted workload-to-AgentID bindings and an allowlisted purpose field."
    }

    precondition {
      condition     = !var.enable_transaction_tokens_inner_profile || var.enable_transaction_tokens_capability_probe
      error_message = "The strict inner Transaction Token profile may run only with the isolated capability gate enabled."
    }
  }

  manager_id = "waiTransactionToken"
  name       = "WAI Transaction Token Manager"

  plugin_descriptor_ref = {
    id = var.transaction_atm_plugin_id
  }

  attribute_contract = {
    # The custom plugin descriptor defines the complete fixed core contract.
    # Repeating those names as extensions makes PingFederate reject ambiguity.
    # The provider requires at least one extension, so use an explicitly
    # unmapped marker that the plugin's claim allowlist never emits.
    extended_attributes = [
      { name = "wai_provider_contract_marker" }
    ]
  }

  configuration = {
    fields = concat([
      {
        name  = "Signing Certificate"
        value = pingfederate_keypairs_signing_key.transaction.key_id
      },
      {
        name  = "Key ID"
        value = pingfederate_keypairs_signing_key.transaction.key_id
      },
      {
        name  = "Token Profile"
        value = local.transaction_token_profile
      },
      {
        name  = "Audience"
        value = local.effective_transaction_audience
      },
      {
        name  = "Transaction Target"
        value = var.transaction_tokens_target
      },
      {
        name  = "Transaction Tool"
        value = var.transaction_tokens_tool
      },
      {
        name  = "Transaction Scope"
        value = local.effective_transaction_scope
      }
      ], [for field in var.transaction_atm_configuration_fields : field if !contains([
        "Token Profile", "Audience", "Transaction Target", "Transaction Tool", "Transaction Scope"
    ], field.name)])
  }

  selection_settings = {
    resource_uris = [
      # PingFederate requires an absolute URI here. The strict Trust Domain is
      # selected by its isolated OAuth resource client and is still minted as
      # the signed JWT audience; it is not valid in this product-specific field.
      var.transaction_audience
    ]
  }
}

resource "pingfederate_oauth_access_token_mapping" "transaction" {
  context = {
    type = "TOKEN_EXCHANGE_PROCESSOR_POLICY"

    context_ref = {
      id = pingfederate_oauth_token_exchange_processor_policy.wai.policy_id
    }
  }

  access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.transaction.manager_id
  }

  attribute_contract_fulfillment = {
    wai_provider_contract_marker = {
      source = {
        type = "NO_MAPPING"
      }
    }

    sub = {
      source = {
        type = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
      }
      value = "user_id"
    }

    workload_id = {
      source = {
        type = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
      }
      value = "workload_id"
    }

    scope = {
      source = {
        type = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
      }
      value = "scope"
    }

    aud = {
      source = {
        type = "TEXT"
      }
      value = local.effective_transaction_audience
    }

    # These remain NO_MAPPING until a trusted server-side transaction
    # metadata / AgentID resolution source is configured.
    agent_id = {
      source = {
        type = "NO_MAPPING"
      }
    }

    agent_instance_id = {
      source = {
        type = "NO_MAPPING"
      }
    }

    transaction_id = {
      source = {
        type = "NO_MAPPING"
      }
    }

    transaction_purpose = {
      source = {
        type = "NO_MAPPING"
      }
    }
  }
}
