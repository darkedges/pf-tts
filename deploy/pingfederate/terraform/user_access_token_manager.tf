resource "pingfederate_oauth_access_token_manager" "user" {
  manager_id = "waiUserAccessToken"
  name       = "WAI User Reference Access Token Manager"

  plugin_descriptor_ref = {
    id = "org.sourceid.oauth20.token.plugin.impl.ReferenceBearerAccessTokenManagementPlugin"
  }

  attribute_contract = {
    extended_attributes = [
      { name = "user_id" }
    ]
  }

  configuration = {
    fields = [
      { name = "Token Length", value = "28" },
      { name = "Token Lifetime", value = "10" },
      { name = "Lifetime Extension Policy", value = "NONE" },
      { name = "Lifetime Extension Threshold Percentage", value = "30" },
      { name = "RPC Timeout", value = "500" },
    ]
  }

  selection_settings = {
    resource_uris = ["urn:wai:user-access"]
  }
}
