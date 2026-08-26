path "kv/data/wai/pingfederate-13-1/administrator" { capabilities = ["read"] }
path "kv/data/wai/pingfederate-13-1/devops" { capabilities = ["read"] }
path "kv/data/wai/pingfederate-13-1/bootstrap-system" { capabilities = ["read"] }
path "kv/data/wai/pingfederate-13-1/oauth/token-exchange" { capabilities = ["read"] }
path "kv/data/wai/pingfederate-13-1/oauth/browser" { capabilities = ["read"] }
path "kv/data/wai/pingfederate-13-1/oauth/lab-user" { capabilities = ["read"] }
path "kv/data/wai/pingfederate-13-1/oauth/mcp-gateway" { capabilities = ["read"] }
path "kv/data/wai/pingfederate-13-1/runtime-ca" { capabilities = ["read"] }
# Read by the JWKS refresher so it can verify the private administrator channel.
path "kv/data/wai/pingfederate-13-1/admin-ca" { capabilities = ["read"] }
