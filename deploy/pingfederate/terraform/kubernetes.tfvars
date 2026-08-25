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

# The authorization server has its own origin, separate from the application it
# authenticates users for. Sharing one hostname made them same-origin to the
# browser, so PingFederate's session cookie rode on every workbench API call and
# the workbench's session cookie was sent to the authorization endpoint.
#
# This base URL is also the issuer of every token this logical TTS signs, so
# consumers allowlist exactly this value. The callback stays on the application
# origin: that is the client, not the authorization server. It remains one exact
# HTTPS URI with no wildcard, query, or fragment.
pf_base_url          = "https://tst.ping.darkedges.com"
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

# The engine is addressed by its public authorization-server hostname and by the
# in-cluster Service. Naming both means in-cluster callers can validate the
# engine directly instead of leaving the cluster to reach it, and nginx can
# verify its upstream by its real name rather than a pinned "localhost".
runtime_server_dns_names = [
  "tst.ping.darkedges.com",
  "wai-pingfederate-engine.wai-pingfederate.svc.cluster.local",
  "wai-pingfederate-engine.wai-pingfederate.svc",
  "wai-pingfederate-engine.wai-pingfederate",
  "wai-pingfederate-engine",
  "localhost",
]

# Activated only after the trust bundle carrying this leaf has reached every
# client. See docs/implementation-notes-task-58.md.
activate_runtime_server_certificate = true
