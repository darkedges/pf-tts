# WAI strict Helm chart

This chart deploys only the opt-in strict Transaction Token call chain: the
non-signing TTS adapter, gateway, MCP server, and API. PingFederate, SPIRE, the
SPIFFE CSI Driver, user authentication, image publication, and secret delivery
are external prerequisites. Kubernetes is not required by the local MVP.

## Trust boundaries

Each Deployment has a distinct Kubernetes ServiceAccount. SPIRE must attest
the namespace and ServiceAccount and issue exactly these identities:

| ServiceAccount | SPIFFE ID |
| --- | --- |
| `wai-tts-adapter` | `spiffe://example.org/tts/adapter` |
| `wai-strict-gateway` | `spiffe://example.org/gateway/mcp-strict` |
| `wai-strict-mcp` | `spiffe://example.org/mcp/demo-strict` |
| `wai-strict-api` | `spiffe://example.org/api/demo-strict` |

Apply the reviewed `ClusterSPIFFEID` examples in `deploy/argocd/spire-identities.yaml`
only after confirming the SPIRE Controller Manager API version in the target
cluster. Do not use a namespace-wide wildcard registration.

The chart reads PingFederate TLS trust and OAuth client credentials from
pre-existing Secrets. It never creates or stores secret values. For GitOps,
provide those Secrets through an approved external secret controller or a
separately managed encrypted-secret workflow.

Set `vault.enabled=true` to manage those destination Secrets with HashiCorp
Vault Secrets Operator. The chart creates namespaced `VaultConnection`,
`VaultAuth`, and `VaultStaticSecret` resources using Kubernetes authentication;
it never stores a Vault token. See `deploy/vault/README.md` for the required KV
keys, least-privilege policy, role binding, and bootstrap CA boundary.

## Render and install

Copy `values-example.yaml` outside source control, replace every image with an
immutable digest, and set the fixed PingFederate endpoints and existing Secret
names. Then validate and install:

```text
helm lint deploy/helm/wai-strict -f /secure/path/values-production.yaml
helm template wai-strict deploy/helm/wai-strict -f /secure/path/values-production.yaml
helm upgrade --install wai-strict deploy/helm/wai-strict --namespace wai-strict --create-namespace -f /secure/path/values-production.yaml
```

The Kubernetes network policy is defense in depth. Exact SPIFFE mTLS identity
and strict Transaction Token verification remain the authorization boundaries.

## Cloudflare-terminated workbench ingress

The chart publishes only `workbench.ping.darkedges.com`, routing to the
existing `wai-web-app` HTTPS Service on port 8446. The Service can be changed
in values, but the schema fixes the reviewed public hostname.

Cloudflare terminates browser TLS. Configure the Tunnel public hostname to use
the in-cluster ingress-nginx HTTP Service, for example
`http://ingress-nginx-controller.ingress-nginx.svc.cluster.local:80`, while
preserving the original Host header. Ingress then uses HTTPS to the workbench
origin. The application's PingFederate OIDC login remains authoritative;
Cloudflare Access headers are not accepted as user or workload identity.

The TTS adapter, strict gateway, MCP server, and API remain private ClusterIP
services. They are deliberately absent from Ingress because Cloudflare
termination cannot preserve the caller's SPIFFE TLS session. Forwarded
certificate or identity headers are not trusted as workload identity.
