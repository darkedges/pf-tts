# HashiCorp Vault secret storage

The Helm integration uses HashiCorp Vault Secrets Operator (VSO) and the Vault
Kubernetes auth method. Install VSO and its CRDs separately and configure a
Vault Kubernetes auth role named `wai-strict` bound only to ServiceAccount
`wai-vault-auth` in namespace `wai-strict`, with audience `vault`.

Attach `wai-strict-policy.hcl` to that role. Do not bind the role to wildcard
namespaces or ServiceAccounts, issue a periodic static token, use AppRole
credentials in Git, or enable TLS verification skipping.

## Required KV v2 records

The default mount is `secret`. Store these exact records using an approved
out-of-band Vault administration workflow:

| Vault path | Required keys | Destination Secret |
| --- | --- | --- |
| `wai/pingfederate/ca` | `ca.pem` | `pingfederate-runtime-ca` |
| `wai/pingfederate/token-exchange-client` | `client-id`, `client-secret` | `pingfederate-token-exchange-client` |
| `wai/workbench` | `oidc-client-secret`, `token-exchange-client-id`, `token-exchange-client-secret` | `wai-web-app-secrets` |

Do not put secret values on a command line, in Helm values, Argo CD parameters,
Terraform state, shell history, or CI output. Load them from protected files or
an approved secret bootstrap pipeline. Delete the protected bootstrap material
after verifying the Vault versions and access policy.

VSO creates the destination Kubernetes Secrets and refreshes them every five
minutes by default. HMAC comparison prevents unchanged values from causing
rollout churn. Relevant Deployments restart when their consumed CA or OAuth
credentials rotate.

The Vault server CA Secret is a bootstrap trust anchor and cannot be fetched
from the Vault connection it authenticates. Provide `vault.caCertSecretRef`
through cluster bootstrap, or leave it empty only when Vault uses a certificate
already trusted by the VSO runtime.

## Importing the existing local development values

After authenticating the Vault CLI through an approved interactive or workload
flow, set `VAULT_ADDR` to the verified HTTPS Vault origin and run:

```text
pwsh -NoProfile -File scripts/import-env-local-to-vault.ps1 -ValidateOnly
make vault-import-local
```

The importer copies only the PingFederate runtime CA, token-exchange client,
and workbench client values. It intentionally excludes PingFederate admin,
PingAuthorize, lab-user, and Ping Identity image-download credentials.

Writes are create-only by default. To rotate records that already exist, first
review the current Vault versions and then explicitly run the script with
`-AllowOverwrite`. Vault KV writes are not transactional; if a later write
fails, review the earlier paths for newly created versions.

The script obtains the currently authenticated token with `vault print token`
and calls the KV v2 HTTPS API with an in-memory JSON body. It follows no
redirects, enforces a 15-second timeout, honors a validated `VAULT_CACERT`, and
never places secret values in command-line arguments or temporary files.
Before writing, it verifies that the configured mount exists and is KV v2. If
your KV v2 engine is not mounted at `secret/`, set `VAULT_KV_MOUNT` or pass the
mount explicitly, for example:

```text
$env:VAULT_KV_MOUNT = 'kv'
make vault-import-local
```

The importer deliberately does not guess another mount after a 404 because
doing so could write credentials into an unintended secrets engine.

## Isolated PingFederate 13.1 privileged bootstrap

Administrator, Ping Identity DevOps, and generated system/bootstrap material
remain outside the default importer above. Task 51 provides a separate explicit
operator path documented in `docs/implementation-notes-task-51.md`. Its runtime
read policy is `wai-pingfederate-13-1-policy.hcl`, and its example Kubernetes
role binds only `wai-pingfederate/wai-pingfederate-vault-auth` with audience
`vault`. Apply the policy and role through an approved Vault administration
workflow; do not commit a Vault token or place secret values in Helm values.
