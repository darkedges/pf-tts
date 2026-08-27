path "kv/data/wai/pingfederate-13-1/runtime-ca" {
  capabilities = ["read"]
}

path "kv/data/wai/pingfederate-13-1/oauth/token-exchange" {
  capabilities = ["read"]
}

path "kv/data/wai/workbench" {
  capabilities = ["read"]
}

# The strict gateway verifies the PingAuthorize decision point against its own
# certificate. This is the public leaf only; the gateway never authenticates to
# the decision point.
path "kv/data/wai/pingauthorize-11-1/runtime-ca" {
  capabilities = ["read"]
}
