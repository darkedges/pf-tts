resource "pingfederate_idp_token_processor" "subject" {
  lifecycle {
    precondition {
      condition     = var.discovery_confirmed
      error_message = "Run PingFederate plugin discovery, review descriptors, then set discovery_confirmed=true."
    }
  }

  processor_id = var.subject_token_processor_id
  name         = var.subject_token_processor_name

  plugin_descriptor_ref = {
    id = var.subject_token_processor_plugin_id
  }

  attribute_contract = {
    core_attributes = [
      { name = "aud" },
      { name = "authorization_details" },
      { name = "client_id" },
      { name = "expires_at" },
      { name = "iss" },
      { name = "scope" },
    ]
    extended_attributes = [
      {
        # This extension must exactly match the validated user-token ATM
        # contract. It is never populated from a token-exchange request field.
        name = "user_id"
      }
    ]
  }

  configuration = {
    fields = concat([
      {
        name  = "Access Token Manager"
        value = pingfederate_oauth_access_token_manager.user.manager_id
      },
      {
        name  = "Scope value as single string"
        value = "true"
      }
    ], var.subject_token_processor_configuration_fields)
  }
}

resource "pingfederate_idp_token_processor" "spire_actor" {
  processor_id = var.actor_token_processor_id
  name         = var.actor_token_processor_name

  plugin_descriptor_ref = {
    id = var.actor_token_processor_plugin_id
  }

  attribute_contract = {
    core_attributes = [
      {
        name = "sub"
      }
    ]
    extended_attributes = []
  }

  configuration = {
    fields = var.actor_token_processor_configuration_fields
  }
}
