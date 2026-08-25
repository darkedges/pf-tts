# WAI strict Helm chart

This chart deploys only the opt-in strict Transaction Token call chain: the
non-signing TTS adapter, gateway, MCP server, API, authenticated workbench, and
bounded in-memory audit collector. PingFederate, SPIRE, the SPIFFE CSI Driver,
image publication, and secret delivery
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
| `wai-strict-workbench` | `spiffe://example.org/agent/web-app` |
| `wai-strict-audit` | `spiffe://example.org/audit/collector` |

Apply the reviewed `ClusterSPIFFEID` examples in `deploy/argocd/spire-identities.yaml`
only after confirming the SPIRE Controller Manager API version in the target
cluster. Do not use a namespace-wide wildcard registration.

The chart reads PingFederate TLS trust, OAuth client credentials, and the
workbench's private in-cluster TLS material from
pre-existing Secrets. It never creates or stores secret values. For GitOps,
provide those Secrets through an approved external secret controller or a
separately managed encrypted-secret workflow.

Set `vault.enabled=true` to manage those destination Secrets with HashiCorp
Vault Secrets Operator. The chart creates namespaced `VaultConnection`,
`VaultAuth`, and `VaultStaticSecret` resources using Kubernetes authentication;
it never stores a Vault token. See `deploy/vault/README.md` for the required KV
keys, least-privilege policy, role binding, and bootstrap CA boundary.

## Render and install

`values-kubernetes.yaml` is the reviewed, secret-free input for revision
`2dcd497b4102`; its application images are pinned to verified multi-platform
manifest digests. The corresponding publication record is
`deploy/images/strict-2dcd497b4102.json`. `values-example.yaml` remains a
template for another environment. Then validate and install:

```text
helm lint deploy/helm/wai-strict -f deploy/helm/wai-strict/values-kubernetes.yaml
helm template wai-strict deploy/helm/wai-strict -f deploy/helm/wai-strict/values-kubernetes.yaml
helm upgrade --install wai-strict deploy/helm/wai-strict --namespace wai-strict --create-namespace -f deploy/helm/wai-strict/values-kubernetes.yaml
```

The Kubernetes network policy is defense in depth. Exact SPIFFE mTLS identity
and strict Transaction Token verification remain the authorization boundaries.

## Cloudflare-terminated workbench ingress

The chart publishes only `workbench.ping.darkedges.com`, routing to the
chart-owned workbench HTTPS Service on port 8446. The schema fixes the reviewed
public hostname, callback URI, and authorization endpoint.

Cloudflare terminates browser TLS. Configure the Tunnel public hostname to use
the in-cluster ingress-nginx HTTP Service, for example
`http://ingress-nginx-controller.ingress-nginx.svc.cluster.local:80`, while
preserving the original Host header. Ingress then uses HTTPS to the workbench
origin. Separate ingress resources validate the workbench and PingFederate
engine upstream certificates using their corresponding Vault-delivered
`ca.crt` trust anchors and the reviewed `localhost` certificate identity. The
application's PingFederate OIDC login remains authoritative;
Cloudflare Access headers are not accepted as user or workload identity.

The TTS adapter, strict gateway, MCP server, API, and audit collector remain private ClusterIP
services. They are deliberately absent from Ingress because Cloudflare
termination cannot preserve the caller's SPIFFE TLS session. Forwarded
certificate or identity headers are not trusted as workload identity.

Only `/as/`, `/pf/`, and `/idp/` are routed to the isolated PingFederate engine
Service. Kubernetes element-aware `Prefix` matching means `/pf-admin-api` and
`/pf-admin` do not match `/pf/`; all non-allowlisted paths remain on the
workbench backend. The PingFederate administrator Service and port 9999 are
never referenced by either ingress.

After deployment and Cloudflare Tunnel configuration, run
`make verify-workbench-public-surface`. The live gate requires JWKS to succeed
on the reviewed hostname, rejects the PingFederate administrator paths and
internal component paths, and rejects the same engine path with an unapproved
Host header. Redirects are disabled so a redirect cannot hide an exposed path.
Before Cloudflare DNS is active, the same live Kubernetes route can be tested
locally with `-IngressOrigin http://localhost`; no other plaintext override is
accepted.
