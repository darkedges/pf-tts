# Reviewed, secret-free Terraform input for the isolated Kubernetes
# PingFederate 13.1 logical TTS (ADR 0011, Task 53).
#
# This file must never contain administrator credentials, OAuth client secrets,
# signing material, or Vault values. Secrets reach Terraform only as TF_VAR_
# process environment read from the exact Vault-synchronized Kubernetes Secrets
# by scripts/run-pf13-kubernetes-terraform.ps1.
#
# The isolated Kubernetes state lives at
# deploy/pingfederate/generated/pf13-kubernetes.tfstate and is distinct from the
# Docker harness state in this directory. Do not apply this file against the
# Docker harness, and never against the shared PingFederate 12.3 release.

# Browser traffic reaches the isolated engine only through the single reviewed
# public hostname. The callback is one exact HTTPS URI with no wildcard, query,
# or fragment.
pf_base_url          = "https://workbench.ping.darkedges.com"
browser_redirect_uri = "https://workbench.ping.darkedges.com/oauth/callback"

# The Kubernetes bootstrap already installed the reviewed Vault-backed Admin TLS
# key. Terraform must not replace the active private key.
manage_local_admin_tls = false

# The deployed adapter, gateway, MCP server, and API implement only the strict
# inner Transaction Token profile (ADR 0010): they request the trust domain as
# the audience and the exact strict scope, and they reject a legacy token. The
# isolated logical TTS must therefore issue that profile, not the legacy WAI JWT.
#
# The capability probe registers the trust domain as an ACCESS_TOKEN_VALIDATION
# client so PingFederate resolves the trust-domain audience. It is a required
# precondition of the inner profile, not an optional diagnostic.
enable_transaction_tokens_capability_probe = true
enable_transaction_tokens_inner_profile    = true
