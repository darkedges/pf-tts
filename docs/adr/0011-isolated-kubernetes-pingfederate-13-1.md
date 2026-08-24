# ADR 0011: Isolated Kubernetes PingFederate 13.1 logical TTS

## Status

Accepted for phased implementation. No application deployment is authorized
until each preceding gate in Tasks 49–57 passes.

## Context

The existing Kubernetes PingFederate deployment at `id.ping.darkedges.com` is
version 12.3 and supports other workloads. It does not contain the reviewed WAI
actor processor required to bind a verified SPIRE JWT-SVID subject to a logical
agent. Upgrading or modifying that shared signing system would expand the
blast radius and make rollback ambiguous.

The strict WAI path was proven against a pinned isolated PingFederate 13.1
runtime. It requires repository-owned plugin code, exact descriptor checks,
dedicated OAuth configuration, and the narrow non-signing TTS adapter from ADR
0010.

## Decision

Deploy a separate PingFederate 13.1 logical TTS in namespace
`wai-pingfederate`. It owns a distinct persistent `/opt/out`, signing state,
administrator credential, OAuth clients, Services, selectors, configuration,
and rollback lifecycle. It must not import or mount state from the shared 12.3
release.

Build a derived runtime image from the digest-pinned official PingFederate
image. It inherits the licensed product binaries and startup hooks, pins Ping's
public `2606` Git server profile, and adds only the tested plugin JAR to the
supported `/opt/in` local profile overlay. The build context must not contain
SDK libraries, secrets, certificates, system keys, generated exports, licenses,
Terraform data, or the generated local `env_vars` file. Publish the derived
image only to the approved registry from a clean revision and deploy it by
manifest digest. Vault supplies bootstrap values at runtime.

The administrator Service and port 9999 remain cluster-private. Browser access
to the authorization server is provided only through explicitly allowlisted
engine paths on `workbench.ping.darkedges.com`. The adapter and workloads use
the internal engine Service. No forwarded header establishes user, agent, or
workload identity.

PingFederate remains the only signer and authority for subject validation,
actor validation, workload-to-AgentID mapping, signed context, scope, and
expiry. The adapter may translate unsupported outer Transaction Token response
semantics but cannot sign, rewrite, or mutate the compact inner token.

## Trust boundaries

- Vault supplies bootstrap and application secrets only to exact
  namespace/ServiceAccount-bound consumers over verified TLS.
- SPIRE PSAT/Kubernetes workload attestation supplies distinct workload
  identities. Kubernetes labels or ServiceAccount names alone are not accepted
  by application authorization.
- Terraform reaches the private administrator API through a temporary bounded
  channel after verifying the exact 13.1 version and plugin descriptors.
- nginx and Cloudflare are routing/TLS boundaries only. Their headers do not
  assert user or workload identity.
- The shared 12.3 release is external and out of scope. Its state, keys,
  credentials, workloads, and Services are never selected or modified.

## Deployment gates

1. Reject a derived runtime build context containing anything outside the
   Dockerfile and tested plugin JAR allowlist.
2. Reject missing, ambiguous, or mutable product/artifact provenance.
3. Reject Vault input or policy that is partial, broad, static-token based, or
   unable to verify TLS.
4. Reject a runtime that is not exact 13.1 or lacks the reviewed plugin classes.
5. Reject Terraform if any workload can assert or substitute its AgentID.
6. Reject workbench routing through the legacy gateway or demo identity.
7. Reject public admin/API routes and internal service ingress.
8. Reject deployment unless all positive and negative end-to-end gates pass
   without raw-token or credential disclosure.

## Rollback

Rollback operates only on the isolated Helm/Argo CD releases, namespace-scoped
application resources, dedicated cluster identity entries, dedicated Vault
policies/roles, and isolated persistent volume. Persistent signing state is
backed up before destructive removal. The shared 12.3 deployment is neither a
rollback source nor a rollback target.

## Rejected alternatives

- Upgrade the shared 12.3 deployment: unrelated consumers and signing state
  would share the migration and rollback blast radius.
- Install WAI plugins into 12.3: the reviewed binary/API contract targets 13.1.
- Reuse its signing state: creates ambiguous logical-TTS ownership.
- Publish a derived PingFederate product image publicly: may redistribute
  licensed product content and risks embedding bootstrap material.
- Use the workbench or demo workload identity interchangeably: violates exact
  runtime-workload to logical-agent binding.
- Expose a new administrator or engine hostname: broadens the public surface
  beyond the reviewed single-hostname requirement.
