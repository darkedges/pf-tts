# Tasks 54 to 56 implementation notes

These three tasks were implemented across commits `a035e90`, `2dcd497`,
`e18c729`, and `8c4f183`. The notes were not written at the time, so this
records what the committed artifacts actually do and what the live Task 57 gate
subsequently proved or disproved about them.

## Task 54 — strict Kubernetes workbench and audit integration

Acceptance criteria: distinct ServiceAccounts and exact SPIFFE IDs for the
workbench and audit collector, the workbench bound only to `urn:agent:web-app`,
Kubernetes-safe OIDC endpoints and exact SPIFFE peers, a deployed audit
collector receiving bounded redacted evidence from every strict hop under one
immutable Transaction ID, bounded in-memory sessions with secure host cookies,
PKCE, state, nonce, exact redirect URI, CSRF origin checks, and no refresh
tokens.

Each component has its own ServiceAccount, and `deploy/argocd/spire-identities.yaml`
issues one exact SPIFFE ID per component through a `ClusterSPIFFEID` whose
template returns `spiffe://example.org/rejected/<pod UID>` when the pod's
ServiceAccount does not match. There is no namespace-wide wildcard registration,
so a pod that carries the right label but the wrong ServiceAccount receives a
deliberately useless identity rather than a usable one.

Docker-only OIDC behaviour was replaced with fixed values:
`OIDC_AUTHORIZATION_ENDPOINT`, `OIDC_TOKEN_ENDPOINT`, and `OIDC_REDIRECT_URI`
are set explicitly on the workbench, and `WEB_PUBLIC_URL` fixes the origin used
for CSRF checks.

The live gate confirmed the browser-facing half: PKCE `S256`, state, nonce, the
exact registered callback, secure session behaviour, a wrong CSRF token
rejected, and a cross-origin submission rejected.

It disproved the audit half as originally delivered. The workbench binding
reached the gateway but not the MCP server or the demo API, so a workbench
transaction produced audit evidence for the first three hops and then vanished
with no event explaining the rejection. This is recorded in full in
[Task 57](implementation-notes-task-57.md); the fix makes every strict hop
verify against one shared reviewed binding set.

## Task 55 — immutable application publication and deployment values

Acceptance criteria: publish every repository-owned runtime artifact from a
clean commit for Linux amd64 and arm64, record registry manifest digests, use
digests rather than tags in reviewed Helm values, commit no registry credential,
render and lint the complete chart with no Secret values, and fail on dirty
publication, missing platform, mutable tag, digest mismatch, missing image, and
a secret-bearing Docker context.

`make image-source-check` refuses to publish from a dirty Git tree, and each
publication target builds with `--platform linux/amd64,linux/arm64` and pushes a
manifest list. `deploy/images/strict-<revision>.json` records the resulting
digests, and `values-kubernetes.yaml` pins them by digest.

One defect surfaced when this task's own machinery was exercised for the Task 57
fix. `TestReviewedPublicationLockMatchesHelmValues` read a single hard-coded
record filename, so republishing would have left the reviewed values pinned to
new digests while the test still validated a stale record — exactly the
digest-mismatch case the task requires to fail. The test now resolves the record
from the source revision the reviewed values declare, and fails if the two
disagree.

The current reviewed input is revision `36d0eb0c2f1b`, which republished only
the three workloads changed by the binding and policy fix. The adapter,
workbench, and audit collector are unchanged since `2dcd497b4102` and keep their
already verified digests.

## Task 56 — single-hostname workbench and PingFederate engine routing

Acceptance criteria: keep `workbench.ping.darkedges.com` as the only new public
hostname, route application paths to the workbench and an explicit allowlist of
`/as`, `/pf`, and `/idp` engine paths to the isolated engine Service, deny admin
API and console paths, keep every internal component private, preserve the
external HTTPS origin and exact redirect URI without trusting Cloudflare
identity headers, and prove with rendering and live negative tests that
forbidden paths and hosts do not reach PingFederate or internal services.

`deploy/helm/wai-strict/templates/ingress.yaml` publishes exactly two Ingress
resources on one host. The workbench takes `/`, and a second Ingress routes only
`/as/`, `/pf/`, and `/idp/` to an `ExternalName` Service that aliases
`wai-pingfederate-engine.wai-pingfederate.svc.cluster.local`. The administrator
Service and port 9999 are never referenced. Because Kubernetes `Prefix` matching
is element-aware, `/pf-admin-api` and `/pf-admin` do not match `/pf/` and fall
through to the workbench, which answers 404.

Both Ingress resources use `backend-protocol: HTTPS` with
`proxy-ssl-verify: "on"` against the corresponding Vault-delivered `ca.crt`, so
nginx validates its upstream rather than terminating blindly.

`scripts/verify-workbench-public-surface.ps1` is the live gate; it passes
against the deployed cluster, with redirects disabled so a redirect cannot hide
an exposed path.

One criterion was not met as delivered, and was found by the Task 57 gate rather
than by this one: "preserve external HTTPS origin" was satisfied for routing but
not inside PingFederate. The runtime base URL was still an internal engine
address, so the hosted login page emitted a `<base href>` and a root-relative
form action pointing at `https://localhost:9031`. Routing was correct and the
login page was unusable. The fix is recorded in
[Task 53](implementation-notes-task-53.md).
