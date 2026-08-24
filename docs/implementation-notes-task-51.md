# Task 51 implementation notes

## Acceptance criteria restatement

Task 51 defines isolated KV v2 records for the PingFederate administrator,
Ping Identity DevOps download identity, bootstrap/system material, each OAuth
client, and runtime CA. Privileged inputs must never pass through the existing
application importer. Import is explicit, create-only by default, bounded,
non-symlinked, complete, internally consistent, TLS-verified, and silent about
secret values. Kubernetes authentication is restricted to the exact namespace,
ServiceAccount, policy, and `vault` audience.

## Trust boundaries

The existing `import-env-local-to-vault.ps1` remains the narrow application
importer and cannot read administrator, DevOps, or system material. The new
privileged importer is a separate operator action requiring
`-IncludePrivilegedBootstrap`. Local protected files are untrusted until their
location, type, size, exact key set, uniqueness, completeness, and cross-field
consistency are validated.

Vault is trusted only at a fixed HTTPS origin with platform TLS validation. The
script refuses `VAULT_SKIP_VERIFY`, redirects, a non-KV-v2 mount, and unauthenticated
operation. It uses in-memory JSON and create-only CAS by default. Because KV
writes are not transactional, errors disclose only the path/status and whether
earlier versions may have been created; response bodies and values are omitted.

The runtime read policy has eight exact paths and no wildcard, list, create, or
administrative capability. The Kubernetes role accepts only ServiceAccount
`wai-pingfederate-vault-auth` in namespace `wai-pingfederate`, policy
`wai-pingfederate-13-1`, and audience `vault`. A pod name, label, different
ServiceAccount, or different namespace cannot authenticate through this role.

## Records

Under the reviewed KV v2 mount `kv`, the fixed base is `wai/pingfederate-13-1`:

- `administrator`
- `devops`
- `bootstrap-system`
- `oauth/token-exchange`
- `oauth/browser`
- `oauth/lab-user`
- `oauth/mcp-gateway`
- `runtime-ca`

Validate without writing:

```text
pwsh -NoProfile -File scripts/import-pingfederate-13-1-bootstrap-to-vault.ps1 -IncludePrivilegedBootstrap -ValidateOnly
```

After reviewing existing Vault versions, create the records with
`make vault-import-pf13-privileged`. Rotation requires the separately visible
`-AllowOverwrite` switch. Static Vault tokens, AppRole secrets, TLS bypass,
wildcard policies, partial inputs, duplicate keys, malformed lines, symlinks,
oversized files/values, and secret-bearing output are rejected by tests.
