# Development-only subject-token issuance. Production must replace this simple
# credential store and ROPC flow with an organization-approved user-facing flow.
resource "pingfederate_password_credential_validator" "lab_user" {
  validator_id = "waiLabUserPCV"
  name         = "WAI Local Lab User"

  plugin_descriptor_ref = {
    id = "org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"
  }

  attribute_contract = {}

  configuration = {
    tables = [{
      name = "Users"
      rows = [{
        fields = [
          { name = "Username", value = var.lab_user_name },
          { name = "Relax Password Requirements", value = "false" },
        ]
        sensitive_fields = [
          { name = "Password", value = var.lab_user_password },
          { name = "Confirm Password", value = var.lab_user_password },
        ]
        default_row = false
      }]
    }]
  }
}

resource "pingfederate_oauth_resource_owner_credentials_mapping" "lab_user" {
  mapping_id = pingfederate_password_credential_validator.lab_user.validator_id

  attribute_contract_fulfillment = {
    USER_KEY = {
      source = { type = "PASSWORD_CREDENTIAL_VALIDATOR" }
      value  = "username"
    }
  }
}

resource "pingfederate_oauth_access_token_mapping" "lab_user" {
  depends_on = [pingfederate_oauth_resource_owner_credentials_mapping.lab_user]

  context = {
    type = "PCV"
    context_ref = {
      id = pingfederate_password_credential_validator.lab_user.validator_id
    }
  }

  access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.user.manager_id
  }

  attribute_contract_fulfillment = {
    user_id = {
      source = { type = "PASSWORD_CREDENTIAL_VALIDATOR" }
      value  = "username"
    }
  }
}

resource "pingfederate_oauth_client" "lab_user" {
  lifecycle {
    ignore_changes = [
      client_auth.secret,
      client_auth.encrypted_secret,
    ]
  }

  client_id   = var.lab_user_client_id
  name        = "WAI Local Lab User Token"
  description = "Development-only client for obtaining an authenticated subject token."

  client_auth = {
    type   = "SECRET"
    secret = var.lab_user_client_secret
  }

  grant_types = ["RESOURCE_OWNER_CREDENTIALS"]

  restrict_scopes = true
  restricted_scopes = [
    local.effective_transaction_scope,
  ]

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.user.manager_id
  }

  restrict_to_default_access_token_manager = true
}
