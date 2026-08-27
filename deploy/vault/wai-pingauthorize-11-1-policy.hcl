path "kv/data/wai/pingauthorize-11-1/administrator" { capabilities = ["read"] }
path "kv/data/wai/pingauthorize-11-1/devops" { capabilities = ["read"] }
# The serving key pair. Read by the product only; the strict gateway's policy
# grants it the public certificate and never this record.
path "kv/data/wai/pingauthorize-11-1/runtime-tls" { capabilities = ["read"] }
path "kv/data/wai/pingauthorize-11-1/runtime-ca" { capabilities = ["read"] }
