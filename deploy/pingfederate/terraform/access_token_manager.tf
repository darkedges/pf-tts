resource "pingfederate_oauth_access_token_manager" "transaction" {
  lifecycle {
    precondition {
      condition = alltrue([
        for required in ["Agent Bindings", "Transaction Purpose"] :
        contains([for field in var.transaction_atm_configuration_fields : field.name], required)
      ])
      error_message = "The transaction ATM requires exact trusted workload-to-AgentID bindings and an allowlisted purpose field."
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
      }
    ], var.transaction_atm_configuration_fields)
  }

  selection_settings = {
    resource_uris = [
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
      value = var.transaction_audience
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
