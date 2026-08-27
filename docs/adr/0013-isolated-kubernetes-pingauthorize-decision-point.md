# ADR 0013: Isolated Kubernetes PingAuthorize decision point

## Status

Accepted. Extends [ADR 0011](0011-isolated-kubernetes-pingfederate-13-1.md) and
[ADR 0012](0012-separate-authorization-server-origin.md); supersedes nothing.

## Context

Task 26 built a PingAuthorize client and Task 27 deployed the product locally in
Docker, but neither reached Kubernetes, and the strict gateway could not have
used them if they had: `cmd/strict-mcp-gateway` hardcoded OPA while only
`cmd/mcp-gateway` honoured `AUTHORIZATION_PROVIDER`. The strict chain is the one
that runs in this cluster, so the adapter was unreachable where it mattered.

The reviewed deployment package was also authored for the non-strict chain. It
guards on `purpose = "system.whoami"` and `scope = "mcp:invoke"`, while the
strict middleware synthesises the purpose from the signed route as
`"<target>:<tool>"` and carries `mcp.system.whoami`. Deployed unchanged it would
have denied every strict call.

## Decision

Deploy PingAuthorize 11.1 as an isolated decision point in namespace
`wai-pingauthorize`, and make the decision point a deployment choice rather than
a compile-time one.

**Selection, not replacement.** The strict gateway reads
`AUTHORIZATION_PROVIDER` the way the non-strict gateway already did. OPA remains
the default: an unchanged deployment keeps the reviewed rego mounted beside the
gateway and renders no PingAuthorize reference at all. An unrecognised value is a
hard failure rather than a fall back to the default, because silently enforcing a
different policy than the operator asked for is worse than refusing to start.

Whichever provider is selected, it is still wrapped by the signed-route
authorizer. The target and tool are re-checked against the signed route before
any policy is consulted: the provider decides, it does not widen the route.

**One package, both chains.** The reviewed package carries the strict tuples
alongside the existing non-strict one. It is generated from a declared rule set
rather than hand-wired, because the graph is a web of cross-referencing
identifiers and is integrity-protected: a `DataStreamFooter` digest covers the
content and the product refuses to start if they disagree.

**A supplied serving identity.** The certificate is generated before the pod
starts and delivered from Vault, rather than left to the product's self-signed
setup certificate. That certificate names the container hostname, which in
Kubernetes is the pod name rather than the Service the gateway addresses, and the
adapter refuses both disabled verification and a `ServerName` override. The
private key and the public certificate are separate Vault records; the strict
gateway's policy grants it the public one only.

**Reachability is the access boundary.** The decision point authenticates no
caller: the adapter sends no credential and `pingauthorize_test.go` actively
forbids an `Authorization` header. Trust is one-way TLS plus the ability to
connect. The NetworkPolicy is therefore the access control, not a
defence-in-depth extra, and it names one namespace and one port. The LDAP port is
not published at all and there is no Ingress.

## Trust boundaries

- PingAuthorize is a remote decision point, not an identity verifier. It cannot
  replace signature, issuer, audience, time, logical-agent, workload, or
  immediate-caller verification, all of which happen before it is consulted.
- Every attribute it receives is server-derived from the verified transaction
  token and the authenticated mTLS peer. A caller cannot supply one.
- Unlike every other hop in the strict chain, this one is **not**
  SPIFFE-authenticated. That is a real asymmetry and is stated here rather than
  left implicit.
- The product holds no Kubernetes API token and reaches nothing but DNS and its
  vendor profile host.

## Consequences

**The vendor profile is fetched from a public host at every startup.** The
product pulls `pingidentity-server-profiles` from github.com during setup, so the
namespace needs egress on 443 and the deployment is not air-gapped. That profile
also ships a permissive sample policy, which makes it the fallback whenever the
reviewed overlay fails to apply. This is accepted rather than vendored, and the
mitigation is the guard below.

**A ConfigMap cannot deliver the `/opt/in` overlay directly.** A ConfigMap volume
is a farm of symlinks into a timestamped directory, and the product's entrypoint
copies `/opt/in` into staging without following them. Mounted that way the
overlay disappears silently and the vendor's sample policy stays in force: the
decision point starts healthy, serves the correct certificate, and permits every
request including forged ones. An init container therefore materialises the
overlay as real files and fails if the reviewed dsconfig is not among them.

**A healthy pod proves nothing about which policy is loaded.** The
`deploymentPackageId` in a decision response distinguishes the reviewed package
from the vendor's, and is the check that must be made when verifying a
deployment.

**The image is pinned by digest with no tag.** PingAuthorize publishes on the
moving `edge` tag, which cannot be pinned to a reviewed build. The digest is
recorded with the observed product version.

## Rejected alternatives

- Replace OPA on the strict path: the deployment would then hard-depend on a
  heavyweight product being healthy, and a decision point that cannot be turned
  off cannot be compared against the one it replaced.
- Let the product self-sign its serving certificate: it would name the pod rather
  than the Service, and the adapter has no override that would accept it.
- Authenticate the gateway to the decision point: the adapter has no place to put
  a credential and its tests forbid one. Changing that is a deliberate change to
  the reviewed client, not a deployment detail.
- Vendor the upstream server profile into this repository: it is a larger
  supply-chain decision than this task should make, and the init-container guard
  addresses the failure it enables.
