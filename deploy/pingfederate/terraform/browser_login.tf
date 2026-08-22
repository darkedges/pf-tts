resource "pingfederate_idp_adapter" "browser_login" {
  adapter_id = "waiBrowserLogin"
  name       = "WAI Browser Hosted Login"

  plugin_descriptor_ref = {
    id = "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"
  }

  attribute_contract = {
    core_attributes = [
      { name = "policy.action", masked = false, pseudonym = false },
      { name = "username", masked = false, pseudonym = true },
    ]
    unique_user_key_attribute = "username"
  }

  attribute_mapping = {
    attribute_contract_fulfillment = {
      "policy.action" = {
        source = { type = "ADAPTER" }
        value  = "policy.action"
      }
      username = {
        source = { type = "ADAPTER" }
        value  = "username"
      }
    }
  }

  configuration = {
    fields = [
      { name = "Challenge Retries", value = "3" },
      { name = "Session State", value = "None" },
      { name = "Login Template", value = "html.form.login.template.html" },
    ]
    tables = [{
      name = "Credential Validators"
      rows = [{
        fields = [{
          name  = "Password Credential Validator Instance"
          value = pingfederate_password_credential_validator.lab_user.validator_id
        }]
        default_row = false
      }]
    }]
  }
}

resource "pingfederate_oauth_idp_adapter_mapping" "browser_login" {
  mapping_id = pingfederate_idp_adapter.browser_login.adapter_id

  attribute_contract_fulfillment = {
    USER_NAME = {
      source = { type = "ADAPTER" }
      value  = "username"
    }
    USER_KEY = {
      source = { type = "ADAPTER" }
      value  = "username"
    }
  }
}

resource "pingfederate_oauth_access_token_mapping" "browser_login" {
  depends_on = [pingfederate_oauth_idp_adapter_mapping.browser_login]

  context = {
    type = "IDP_ADAPTER"
    context_ref = {
      id = pingfederate_idp_adapter.browser_login.adapter_id
    }
  }

  access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.user.manager_id
  }

  attribute_contract_fulfillment = {
    user_id = {
      source = { type = "ADAPTER" }
      value  = "username"
    }
  }
}

resource "pingfederate_openid_connect_policy" "browser_login" {
  policy_id = "waiBrowserOIDC"
  name      = "WAI Browser OIDC Policy"

  access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.user.manager_id
  }

  attribute_contract = {}

  attribute_mapping = {
    attribute_contract_fulfillment = {
      sub = {
        source = { type = "TOKEN" }
        value  = "user_id"
      }
    }
  }

  id_token_lifetime                       = 5
  include_user_info_in_id_token           = false
  return_id_token_on_refresh_grant        = false
  return_id_token_on_token_exchange_grant = false
}

resource "pingfederate_oauth_client" "browser" {
  lifecycle {
    ignore_changes = [
      client_auth.secret,
      client_auth.encrypted_secret,
    ]

    precondition {
      condition = alltrue([
        var.browser_client_id != var.token_exchange_client_id,
        var.browser_client_id != var.lab_user_client_id,
        var.browser_client_id != pingfederate_oauth_client.mcp_gateway.client_id,
      ])
      error_message = "The browser, password, token-exchange, and resource-server OAuth clients must remain distinct."
    }

    precondition {
      condition     = var.browser_scopes == toset(["openid", var.transaction_scope])
      error_message = "The browser client scopes must be exactly openid and the configured transaction scope."
    }
  }

  client_id   = var.browser_client_id
  name        = "WAI Browser Application"
  description = "Confidential BFF client for PingFederate-hosted Authorization Code login."
  enabled     = true

  client_auth = {
    type   = "SECRET"
    secret = var.browser_client_secret
  }

  grant_types                         = ["AUTHORIZATION_CODE"]
  redirect_uris                       = [var.browser_redirect_uri]
  restricted_response_types           = ["code"]
  require_proof_key_for_code_exchange = true
  bypass_approval_page                = false

  restrict_scopes   = true
  restricted_scopes = var.browser_scopes

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.user.manager_id
  }
  restrict_to_default_access_token_manager = true

  oidc_policy = {
    policy_group = {
      id = pingfederate_openid_connect_policy.browser_login.policy_id
    }
  }

  depends_on = [
    pingfederate_oauth_access_token_mapping.browser_login,
    pingfederate_oauth_idp_adapter_mapping.browser_login,
  ]
}
