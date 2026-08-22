variable "pf_base_url" {
  description = "Human-readable PingFederate base URL used in outputs/documentation."
  type        = string
  default     = "https://localhost:9031"
}

variable "trust_domain" {
  description = "SPIFFE trust domain used by the local SPIRE lab."
  type        = string
  default     = "example.org"
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
    "spiffe://example.org/agent/demo" = "urn:agent:demo"
  }

  validation {
    condition     = length(var.agent_bindings) > 0
    error_message = "At least one SPIFFE-to-AgentID binding is required."
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
