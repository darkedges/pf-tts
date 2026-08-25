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
    # The trusted SPIRE JWKS identifies which workload identities this logical
    # TTS will accept as an actor. It belongs to exactly one SPIRE trust domain,
    # so a deployment that runs against a different SPIRE server must supply that
    # server's own keys rather than inherit another environment's.
    fields = var.spire_jwks == "" ? var.actor_token_processor_configuration_fields : concat(
      [{ name = "SPIRE JWKS", value = var.spire_jwks }],
      [for field in var.actor_token_processor_configuration_fields : field if field.name != "SPIRE JWKS"]
    )
  }
}
