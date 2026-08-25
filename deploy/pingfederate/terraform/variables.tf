variable "pf_base_url" {
  description = "Authoritative PingFederate runtime base URL. It is the external HTTPS origin the browser reaches, the origin hosted login pages render against, and the issuer of the tokens this logical TTS signs. Consumers must allowlist this exact value."
  type        = string
  default     = "https://localhost:9031"

  validation {
    condition     = can(regex("^https://[A-Za-z0-9.-]+(:[0-9]+)?$", var.pf_base_url))
    error_message = "pf_base_url must be an HTTPS origin with no path, query, or fragment."
  }
}

variable "manage_local_admin_tls" {
  description = "Generate local-development Admin TLS in Terraform. Set false when Kubernetes bootstrap has already installed the reviewed Vault-backed key."
  type        = bool
  default     = true
}

variable "runtime_server_dns_names" {
  description = "Exact DNS names the PingFederate engine is addressed by. The first entry becomes the common name. Empty leaves the bootstrap certificate in place, which is correct for the Docker harness."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for name in var.runtime_server_dns_names :
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?([.][a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", name))
    ]) && length(var.runtime_server_dns_names) == length(distinct(var.runtime_server_dns_names))
    error_message = "runtime_server_dns_names must be distinct lowercase DNS names with no wildcard, scheme, port, or path."
  }
}

variable "activate_runtime_server_certificate" {
  description = "Serve the generated runtime certificate. Flip this only after every client trusts the new leaf, because activation swaps the engine's TLS identity immediately."
  type        = bool
  default     = false
}

variable "admin_console_key_id" {
  description = "Key pair the administrator console keeps serving. It is reached only through a bounded loopback port-forward, so it is not rotated alongside the engine."
  type        = string
  default     = "wai-local-runtime-tls"
}

variable "trust_domain" {
  description = "SPIFFE trust domain used by the local SPIRE lab."
  type        = string
  default     = "example.org"
}

variable "enable_transaction_tokens_capability_probe" {
  description = "Create an isolated-only trust-domain audience selector for Task 34 capability testing. Never enable in the normal workbench state."
  type        = bool
  default     = false
}

variable "enable_transaction_tokens_inner_profile" {
  description = "Enable the isolated-only strict draft-11 inner JWT profile. Keep false in normal workbench state."
  type        = bool
  default     = false
}

variable "transaction_tokens_scope" {
  description = "Fixed narrow scope used only by the isolated strict inner Transaction Token profile."
  type        = string
  default     = "mcp.system.whoami"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", var.transaction_tokens_scope))
    error_message = "The strict Transaction Token scope must be one bounded scope token."
  }
}

variable "transaction_tokens_target" {
  description = "Fixed trusted target used only by the isolated strict inner Transaction Token profile."
  type        = string
  default     = "demo"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", var.transaction_tokens_target))
    error_message = "The strict Transaction Token target must be a bounded identifier."
  }
}

variable "transaction_tokens_tool" {
  description = "Fixed trusted tool used only by the isolated strict inner Transaction Token profile."
  type        = string
  default     = "system.whoami"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", var.transaction_tokens_tool))
    error_message = "The strict Transaction Token tool must be a bounded identifier."
  }
}

variable "actor_audience" {
  description = "Audience requested in the agent JWT-SVID and accepted by PingFederate."
  type        = string
  default     = "urn:pingfederate:wai:token-exchange"
}

variable "transaction_audience" {
  description = "Audience of the PingFederate-issued transaction access token."
  type        = string
  default     = "urn:wai:mcp-gateway"
}

variable "exchange_target_audience" {
  description = "PingFederate OAuth resource-server client selected by the RFC 8693 audience parameter."
  type        = string
  default     = "mcp-gateway"
}

variable "mcp_gateway_client_secret" {
  description = "MCP gateway resource-server OAuth client secret. Inject outside committed files."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.mcp_gateway_client_secret) >= 32
    error_message = "The MCP gateway OAuth client secret must contain at least 32 characters."
  }
}

variable "transaction_scope" {
  description = "Scope allowed for the first MCP transaction-token flow."
  type        = string
  default     = "mcp:invoke"
}

variable "transaction_token_lifetime_seconds" {
  description = "Desired transaction-token lifetime. The selected ATM plugin may express this in minutes; see README."
  type        = number
  default     = 20

  validation {
    condition     = var.transaction_token_lifetime_seconds > 0 && var.transaction_token_lifetime_seconds <= 60
    error_message = "The MVP transaction token lifetime must be between 1 and 60 seconds."
  }
}

variable "token_exchange_client_id" {
  description = "OAuth client ID used by the agent for RFC 8693 token exchange."
  type        = string
  default     = "wai-agent-token-exchange"
}

variable "token_exchange_client_secret" {
  description = "OAuth client secret. Inject with TF_VAR_token_exchange_client_secret. Do not commit it."
  type        = string
  sensitive   = true
}

variable "lab_user_name" {
  description = "Development-only authenticated user name placed in the subject-token user_id contract."
  type        = string
  default     = "demo-user"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$", var.lab_user_name))
    error_message = "The lab user name must be a simple 3-64 character identifier."
  }
}

variable "lab_user_password" {
  description = "Development-only user password. Inject with TF_VAR_lab_user_password; never commit it."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.lab_user_password) >= 14
    error_message = "The lab user password must contain at least 14 characters."
  }
}

variable "lab_user_client_id" {
  description = "Development-only OAuth client used to obtain a subject access token."
  type        = string
  default     = "wai-lab-user"
}

variable "lab_user_client_secret" {
  description = "Development-only OAuth client secret. Inject with TF_VAR_lab_user_client_secret; never commit it."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.lab_user_client_secret) >= 32
    error_message = "The lab user OAuth client secret must contain at least 32 characters."
  }
}

variable "browser_client_id" {
  description = "Dedicated confidential OAuth/OIDC client used only by the browser BFF."
  type        = string
  default     = "wai-web-app"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$", var.browser_client_id))
    error_message = "The browser OAuth client ID must be a simple 3-64 character identifier."
  }
}

variable "browser_client_secret" {
  description = "Browser BFF OAuth client secret. Inject with TF_VAR_browser_client_secret; never commit it."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.browser_client_secret) >= 32
    error_message = "The browser OAuth client secret must contain at least 32 characters."
  }
}

variable "browser_redirect_uri" {
  description = "Exact HTTPS callback URI registered for the local browser BFF. Wildcards, query strings, and fragments are forbidden."
  type        = string
  default     = "https://localhost:8446/oauth/callback"

  validation {
    condition = (can(regex("^https://[A-Za-z0-9.-]+(:[0-9]+)?/[^?#*]+$", var.browser_redirect_uri)) &&
      !strcontains(var.browser_redirect_uri, "*") &&
      !strcontains(var.browser_redirect_uri, "?") &&
    !strcontains(var.browser_redirect_uri, "#"))
    error_message = "The browser redirect URI must be one exact HTTPS URI without credentials, wildcards, query, or fragment."
  }
}

variable "browser_scopes" {
  description = "Exact scopes available to the browser Authorization Code client."
  type        = set(string)
  default     = ["openid", "mcp:invoke"]

  validation {
    condition     = length(var.browser_scopes) == 2 && contains(var.browser_scopes, "openid") && alltrue([for scope in var.browser_scopes : length(trimspace(scope)) > 0])
    error_message = "The browser client must have exactly two non-empty scopes including openid."
  }
}

variable "subject_token_processor_id" {
  description = "PingFederate token processor instance used to validate subject/user access tokens."
  type        = string
  default     = "waiUserAccessToken"
}

variable "subject_token_processor_name" {
  type    = string
  default = "WAI User Access Token Processor"
}

variable "subject_token_processor_plugin_id" {
  description = "Plugin descriptor ID for the PingFederate OAuth token processor in the deployed PF release."
  type        = string
}

variable "subject_token_processor_configuration_fields" {
  description = "Plugin-specific fields required by the subject-token processor."
  type = list(object({
    name  = string
    value = optional(string)
  }))
  default = []
}

variable "actor_token_processor_id" {
  description = "PingFederate JWT Token Processor instance used to validate SPIRE JWT-SVID actor tokens."
  type        = string
  default     = "waiSpireJwtSvid"
}

variable "actor_token_processor_name" {
  type    = string
  default = "WAI SPIRE JWT-SVID Processor"
}

variable "actor_token_processor_plugin_id" {
  description = "Plugin descriptor ID for JWT Token Processor 2.0 in the deployed PF release."
  type        = string
}

variable "spire_jwks" {
  description = "Exact SPIRE JWT-SVID JWKS the actor token processor trusts. Empty keeps the value supplied in actor_token_processor_configuration_fields, which is correct for the Docker harness. The Kubernetes gate sets this from the in-cluster SPIRE server's own bundle so the isolated logical TTS never trusts another trust domain's signing keys."
  type        = string
  default     = ""
  sensitive   = false

  validation {
    condition = var.spire_jwks == "" || try(
      length([for key in jsondecode(var.spire_jwks).keys : key if try(key.kid, "") != ""]) == length(jsondecode(var.spire_jwks).keys)
      && length(jsondecode(var.spire_jwks).keys) > 0,
      false
    )
    error_message = "spire_jwks must be a JWKS document whose every key carries a non-empty kid."
  }
}

variable "actor_token_processor_configuration_fields" {
  description = "Plugin-specific JWT Token Processor 2.0 fields (issuer, JWKS URL, audience, etc.)."
  type = list(object({
    name  = string
    value = optional(string)
  }))
  default = []
}

variable "transaction_atm_plugin_id" {
  description = "Plugin descriptor ID for the JWT bearer access-token manager used for transaction tokens."
  type        = string
}

variable "transaction_atm_configuration_fields" {
  description = "Plugin-specific fields for the transaction JWT Access Token Manager."
  type = list(object({
    name  = string
    value = optional(string)
  }))
  default = []
}

variable "agent_bindings" {
  description = "Trusted SPIFFE workload to logical AgentID mapping."
  type        = map(string)

  default = {
    "spiffe://example.org/agent/demo"    = "urn:agent:demo"
    "spiffe://example.org/agent/web-app" = "urn:agent:web-app"
  }

  validation {
    condition = length(var.agent_bindings) > 0 && length(var.agent_bindings) <= 100 && alltrue([
      for workload, agent in var.agent_bindings :
      can(regex("^spiffe://[a-z0-9.-]+/.+$", workload)) && can(regex("^urn:agent:[A-Za-z0-9._:-]+$", agent))
    ])
    error_message = "Agent bindings must contain 1-100 exact SPIFFE IDs mapped to bounded urn:agent identifiers."
  }
}

variable "allowed_transaction_purposes" {
  description = "Purpose identifiers allowed in the MVP."
  type        = set(string)
  default = [
    "customer.read",
    "system.whoami",
  ]
}


variable "discovery_confirmed" {
  description = "Safety gate confirming PF 13.1 plugin descriptors were discovered and reviewed."
  type        = bool
  default     = false
}
