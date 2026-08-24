# Implementation Notes: Task 48

## Outcome

Task 48 adds optional Helm and Argo CD support for the isolated strict
Transaction Token call chain. It does not deploy Kubernetes resources or alter
the Docker workbench.

## Trust boundaries

Application pods obtain workload identity only from the read-only SPIFFE CSI
Workload API socket. Kubernetes ServiceAccount tokens are not mounted. Each
component uses a distinct ServiceAccount, and the SPIRE Controller Manager
examples check the actual Pod ServiceAccount before issuing an
application-accepted SPIFFE ID. A differently addressed identity remains
rejected by the application's exact peer policies.

PingFederate TLS trust and OAuth client credentials enter through existing
Kubernetes Secrets. The chart and Argo CD manifests contain no Secret resource
or credential value. Image digests can be pinned, policy is read-only, pods run
non-root with no added capabilities, and NetworkPolicy is defense in depth
around cryptographic caller authentication.

## Failure cases

Repository tests fail on embedded Secret manifests, service-account token
mounts, privileged or writable containers, `latest` images, writable policy,
or missing ServiceAccount identity binding. Helm schema and template validation
reject missing endpoints, image coordinates, CA Secret, and OAuth Secret.

Task 48 intentionally does not install SPIRE CRDs, create credentials, publish
images, contact a Kubernetes cluster, or cut over the normal workbench.

The only external ingress route is `workbench.ping.darkedges.com`. Cloudflare
terminates browser TLS and ingress-nginx re-encrypts to the existing workbench
HTTPS Service. The adapter, gateway, MCP server, and API remain private because
TLS termination cannot preserve the original caller's SPIFFE TLS session. A
test rejects passthrough/public routes for those internal services.

HashiCorp Vault integration uses Vault Secrets Operator with namespaced
Kubernetes authentication. Git contains only Vault paths, destination Secret
names, and a least-privilege read policy. Tests reject embedded Kubernetes
Secret manifests, AppRole/static Vault credentials, and disabled Vault TLS
verification. The Vault server CA remains an explicit bootstrap trust anchor.
