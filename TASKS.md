# Staged Codex Tasks

Complete these tasks in order. Do not skip ahead.

## Task 00 — Repository baseline

Create a Go module and the initial directory structure.

Acceptance criteria:

- `go test ./...` passes.
- Add a minimal CI workflow later only after the module compiles locally.
- No application code depends on Kubernetes.
- Add `README.md`, `AGENTS.md`, and architecture docs.

## Task 01 — Core identity model

Implement strongly typed domain structures:

- `UserIdentity`
- `AgentIdentity`
- `WorkloadIdentity`
- `TransactionIdentity`
- `AuthorizationContext`
- `RequestIdentityContext`

Requirements:

- `AgentIdentity.ID` and `WorkloadIdentity.SPIFFEID` are distinct.
- Constructors validate required fields.
- Do not store raw tokens in domain structs except in transport-specific request types.
- Add unit tests for invalid/empty identifiers.

## Task 02 — Configuration model

Implement YAML/JSON-friendly configuration under `internal/config`.

Required sections:

- server
- spiffe
- pingfederate
- transaction
- agents
- mcp
- audit

Validate:

- PingFederate issuer/token endpoint configured.
- Transaction audience configured.
- transaction TTL max <= configured safety maximum.
- every logical agent has at least one allowed SPIFFE ID.
- duplicate Agent IDs are rejected.
- duplicate SPIFFE-to-agent bindings are rejected unless explicitly modeled later.

Do not add environment-variable parsing until the config model is tested.

## Task 03 — SPIFFE provider interface

Create a core workload identity boundary.

Required operations:

- fetch JWT-SVID for one or more audiences,
- create/obtain an X.509 source suitable for mTLS,
- expose the selected SPIFFE ID,
- close underlying resources cleanly.

The interface belongs in a core package.
The SPIRE/go-spiffe implementation belongs in an adapter package.

Test with fakes before talking to a real SPIRE agent.

## Task 04 — Self-contained SPIRE lab

Add a repository-owned local SPIRE environment under `deploy/spire/`.

Use the official SPIRE Server and SPIRE Agent container images pinned to a known release.

The initial lab must provide:

- one SPIRE Server,
- one SPIRE Agent,
- a dedicated local trust domain,
- join-token node attestation for development bootstrap,
- Docker workload attestation,
- a shared Workload API Unix socket,
- registration entries for:
  - demo-agent,
  - mcp-gateway,
  - demo-mcp-server,
  - demo-api,
- one probe command that obtains a JWT-SVID through the Workload API.

Use Docker labels as the workload selector in the lab.

Example:

```text
docker:label:wai.workload:demo-agent
```

Acceptance criteria:

- server configuration validates,
- agent configuration validates,
- bootstrap script generates a fresh join token and trust bundle,
- agent attests to server,
- workload entries can be registered idempotently,
- a labeled probe container can fetch a JWT-SVID for:
  `spiffe://example.org/agent/demo`,
- the JWT-SVID has the requested PingFederate actor audience,
- no private key or join token is committed to the repository,
- generated bootstrap material is gitignored,
- documentation explicitly says join-token attestation is lab-only.

Do not require Kubernetes.

## Task 05 — SPIRE/go-spiffe adapter

Use `github.com/spiffe/go-spiffe/v2`.

Implement:

- configurable Workload API endpoint,
- JWT-SVID fetch,
- X509 source,
- exact expected SPIFFE ID selection,
- explicit failure on zero or multiple unexpected SVIDs.

Support endpoint configuration rather than hard-coded paths.

Document examples for:

- Linux Unix socket,
- Windows SPIRE agent named pipe.

Integration tests may be build-tagged if they require a running SPIRE agent.

## Task 06 — Agent binding registry

Implement trusted binding:

`SPIFFEID -> allowed logical AgentID(s)`

MVP recommendation: one SPIFFE ID maps to one logical AgentID.

The client must not be able to choose an arbitrary AgentID during exchange.

Expose:

```go
ResolveAgent(spiffeID string) (AgentIdentity, error)
```

Add tests:

- known mapping succeeds,
- unknown workload fails,
- conflicting mapping fails at configuration load,
- caller-supplied AgentID cannot override resolved identity.


## Task 07 — PingFederate Terraform baseline

Add PingFederate 13.1 Admin API discovery before applying plugin-backed resources.

Discovery must query `/version`, `/idp/tokenProcessors/descriptors`, and `/oauth/accessTokenManagers/descriptors`, persist raw descriptor reports outside Git, and generate a local version-specific tfvars file. A Terraform precondition must block creation until discovery has been reviewed.


Use the official `pingidentity/pingfederate` Terraform provider as the authoritative PingFederate configuration mechanism.

Create `deploy/pingfederate/terraform`.

Terraform must manage:

- subject/user token processor,
- SPIRE JWT-SVID actor token processor,
- Token Exchange Processor Policy,
- actor-token-required behavior,
- dedicated transaction-token Access Token Manager,
- access-token mapping,
- token-exchange OAuth client.

Do not hard-code or commit secrets.

Do not guess plugin-specific configuration field names. Capture the exact PingFederate 13.1 plugin descriptors and pin them in a version-specific lab configuration.

Initially map only identities proven by token processors:

- verified subject -> `user_id`,
- verified actor subject -> `workload_id`.

Acceptance criteria:

- `terraform fmt -check` passes,
- `terraform validate` passes after the version-specific plugin descriptor inputs are populated,
- OAuth client references the TEPP,
- TEPP requires actor token,
- output ATM is dedicated to transaction tokens,
- token-exchange client is restricted to the intended scope and ATM,
- Terraform state is excluded from Git,
- secrets are supplied outside committed files.

## Task 08 — PingFederate RFC 8693 client

Implement a token exchange client.

Input:

- subject token,
- actor token,
- subject token type,
- actor token type,
- audience,
- optional scope.

Required HTTP behavior:

- POST form body.
- never place tokens in URL/query.
- explicit timeout.
- injectable `http.Client`.
- redact tokens from errors/logs.
- parse OAuth error responses safely.
- do not retry 4xx authentication/authorization errors automatically.

Output:

- access token,
- issued token type when supplied,
- token type,
- expires_in,
- scope.

Add an `httptest.Server` suite validating exact form parameters.

## Task 09 — Transaction claim model

Implement typed verified claims separate from raw JWT parsing.

Required claims for MVP:

- issuer,
- subject,
- audience,
- expiry,
- issued-at,
- `jti`,
- logical agent ID,
- agent instance ID where required,
- SPIFFE workload ID,
- transaction ID,
- purpose.

Reject missing required claims.

Do not support arbitrary map-based authorization in core code.

## Task 10 — PingFederate transaction JWT verifier

Implement a verifier that:

- obtains keys from the configured PingFederate JWKS source,
- enforces configured issuer,
- enforces required audience,
- enforces an explicit algorithm allowlist,
- validates `exp`, `nbf` when present, and `iat`,
- requires transaction/agent/workload claims,
- applies small configurable clock skew,
- supports signing-key rotation by `kid`.

The verifier returns verified typed claims.

Tests:

- good token,
- bad signature,
- unknown `kid`,
- wrong issuer,
- wrong audience,
- expired token,
- not-yet-valid token,
- missing agent,
- missing workload,
- missing transaction ID.

## Task 11 — Transaction context middleware

Implement net/http middleware that:

1. extracts a bearer transaction token,
2. verifies it,
3. obtains the authenticated immediate SPIFFE caller identity from the TLS connection/context,
4. evaluates caller binding policy,
5. places a typed `RequestIdentityContext` into `context.Context`.

Downstream handlers must never parse JWTs themselves.

Add:

```go
identity.FromContext(ctx)
```

with a safe return shape.

## Task 12 — SPIFFE mTLS HTTP client/server helpers

Implement helpers using go-spiffe TLS facilities.

Requirements:

- X.509-SVID rotation must not require process restart.
- authorize explicit SPIFFE IDs or trust-domain policy; never default production helpers to `AuthorizeAny`.
- keep demo-only permissive helpers clearly named and impossible to enable accidentally in production configuration.
- capture peer SPIFFE ID for request middleware.

Unit-test authorization policy separately.

## Task 13 — Minimal MCP gateway

Implement a remote MCP gateway over Streamable HTTP.

Target the current MCP protocol revision used by the selected Go MCP library, but keep MCP transport parsing isolated from the identity middleware.

Responsibilities:

- require verified transaction context,
- expose only configured MCP servers/tools,
- route tool calls,
- propagate immutable transaction token downstream,
- use SPIFFE mTLS downstream,
- add transaction/user/agent/workload IDs to structured logs,
- never log tool arguments marked sensitive.

For the 2026-07-28 MCP protocol, preserve/validate the standard routing headers as required by the selected SDK and spec.

## Task 14 — Demo MCP server

Create a tiny server with two tools:

- `customer.get`
- `system.whoami`

`system.whoami` returns only safe verified metadata:

- user ID,
- logical agent ID,
- workload SPIFFE ID from the transaction,
- immediate caller SPIFFE ID,
- transaction ID,
- purpose.

It must not return raw tokens.

## Task 15 — Protected demo API

Implement a normal HTTP API called by the MCP server over SPIFFE mTLS.

Require the same immutable transaction JWT and validate the immediate MCP server workload.

Return sample data only when both transaction authorization and immediate-caller policy pass.

## Task 16 — Demo agent

Implement a CLI agent that can:

1. accept or obtain a demo user access token,
2. get its JWT-SVID from SPIRE,
3. create a cryptographically random/time-sortable agent instance ID,
4. perform PingFederate token exchange,
5. call the MCP gateway.

Modes:

- `normal`
- `spoof-agent`
- `wrong-audience`
- `expired-token` where test infrastructure permits
- `direct-to-api`

Attack modes must demonstrate expected rejection.

## Task 17 — Structured audit

Add structured audit events:

- transaction.exchange.requested
- transaction.exchange.succeeded
- transaction.exchange.failed
- transaction.verify.succeeded
- transaction.verify.failed
- mcp.tool.requested
- mcp.tool.allowed
- mcp.tool.denied
- downstream.request

Every event should carry, when known:

- transaction ID,
- user ID,
- agent ID,
- transaction workload SPIFFE ID,
- immediate caller SPIFFE ID,
- target,
- decision,
- reason code.

Never include raw credentials.

## Task 18 — PingFederate lab configuration guide

Document the exact manual configuration required for a lab:

- OAuth client,
- token exchange grant enabled,
- Token Exchange Processor Policy,
- subject-token processor,
- actor-token JWT validation using SPIRE trust material,
- attribute contract,
- SPIFFE ID → Agent ID mapping,
- access token manager / JWT generator,
- output claim mapping,
- short TTL,
- audience restrictions.

Where PingFederate product UI/API details vary by version, document the expected logical configuration and mark version-specific names.

## Task 19 — SPIRE lab configuration

Provide SPIRE Server/Agent examples for:

- demo-agent,
- mcp-gateway,
- demo-mcp-server,
- demo-api.

Use different SPIFFE IDs for each workload.

Do not use one shared SVID for the whole demo.

## Task 20 — Docker Compose/lab orchestration

Goal: minimize setup while keeping PingFederate and SPIRE externalizable.

Provide profiles:

- app-only: connects to existing PingFederate + SPIRE.
- local-lab: starts local demo workloads and any permitted local SPIRE components.

Do not embed secrets in Compose files.

## Task 21 — End-to-end tests

Automate where practical:

PASS:
- valid user + valid agent.
- transaction ID consistent end-to-end.

FAIL:
- forged AgentID.
- wrong SPIFFE workload.
- wrong audience.
- expired token.
- unapproved MCP target.
- direct call to protected API from agent when API only allows MCP-server caller.
- missing transaction token.

Assert no raw bearer token appears in captured logs.

## Task 22 — Windows validation

Build/test supported commands for Windows.

Validate the SPIRE Workload API endpoint model with Windows named-pipe configuration.

Do not claim Windows parity until an end-to-end run has been completed on Windows.

## Task 23 — Threat model and ADRs

Write threat scenarios for:

- compromised AI agent,
- compromised MCP gateway,
- compromised MCP server,
- compromised downstream API,
- stolen subject token,
- stolen JWT-SVID,
- stolen transaction token,
- token replay,
- SPIRE compromise,
- PingFederate compromise,
- signing-key compromise,
- confused deputy,
- SSRF/routing abuse in MCP gateway,
- malicious tool input.

Add ADRs for:

- immutable transaction token,
- separate immediate-caller mTLS identity,
- PingFederate as issuer,
- SPIRE as workload identity provider,
- logical AgentID separate from SPIFFEID.

## Task 24 — Trusted MCP authorization policy

Goal: authorize verified delegated transactions at the MCP gateway using a
repository-owned policy rather than caller assertions.

Acceptance criteria:

- Match verified AgentID, transaction workload SPIFFE ID, purpose, required
  scopes, MCP target, and tool.
- Load policy from a bounded, strict JSON document mounted read-only.
- Reject unknown fields, empty policies, missing bindings, and ambiguous
  duplicate rules.
- Deny missing verified identity, unknown tuples, and missing scopes.
- Emit structured allow/deny audit events without credentials.
- An allowed request must fail closed if its audit event cannot be written.
- Add unit failure cases and exercise the allow path in the live lab.

## Task 25 — OPA authorization policy adapter

Goal: evaluate the trusted MCP authorization policy with OPA while preserving
an adapter boundary for a later PingAuthorize implementation.

Acceptance criteria:

- Compile a repository-owned Rego policy at gateway startup.
- Evaluate OPA in-process using only typed, verified identity and route input.
- Keep the Rego file on a read-only container mount with a 1 MiB load limit.
- Disable OPA network-capable built-ins.
- Require exactly one boolean `data.wai.authz.allow` decision.
- Deny undefined, false, non-boolean, cancelled, timed-out, and failed results.
- Preserve the request context through the authorizer boundary.
- Add failure tests for identity conflict, ambiguous result, invalid policy,
  cancellation, and attempted outbound policy access.

## Post-MVP backlog

Only after Tasks 00–23:

- **Priority 1 — Interactive PingFederate-authenticated application UI.**
  Provide a browser application where a user signs in through PingFederate and
  invokes the configured services through the existing agent/gateway flow.
  Use OAuth 2.0 Authorization Code with PKCE and a PingFederate-hosted login;
  the application must never collect, proxy, log, or persist PingFederate
  credentials. The main interaction area occupies the left two-thirds of the
  screen. A selectable audit trail occupies the right third and correlates
  every interaction by TransactionID across agent, gateway, MCP server, and
  API. Selecting an event shows safe request/response metadata for each hop,
  with bearer tokens, cookies, authorization codes, client secrets, private
  material, and sensitive tool arguments structurally excluded or redacted.
  Require issuer, audience, state, nonce, PKCE, redirect-URI, CSRF, session,
  logout, and authorization checks; do not treat browser-supplied identity or
  audit fields as trusted. Add end-to-end tests for successful login and
  interaction plus forged state, wrong issuer/audience, unauthenticated access,
  unauthorized audit access, cross-user audit isolation, and credential
  leakage. Follow the ordered design in `docs/ui-plan.md`.
- richer authorization policies,
- Ping Authorize integration,
- OPA/Cedar adapter,
- transparent proxy/interception mode,
- Kubernetes deployment/sidecar/operator,
- transaction proof-of-possession,
- token replay cache where justified,
- cloud workload attestation,
- admin API/UI,
- multi-trust-domain federation,
- per-tool derived/downscoped tokens,
- WIT-SVID investigation.

## Task 26 — PingAuthorize policy adapter

Goal: evaluate the same trusted MCP authorization input through the
PingAuthorize JSON PDP API without treating a remote `PERMIT` as sufficient
when the response is incomplete or carries unfulfilled obligations.

Acceptance criteria:

- Send only typed, verified user, agent, workload, immediate-caller,
  transaction, scope, target, and tool values to a fixed HTTPS
  `/governance-engine` endpoint.
- Require a bounded HTTP client, decision timeout, response size, exact JSON
  schema, successful policy status, and consistent `PERMIT` plus `authorised`
  values.
- Deny unavailable, timed-out, cancelled, malformed, oversized, ambiguous, or
  contradictory responses.
- Deny unfulfilled obligatory statements until a named obligation handler is
  implemented and tested.
- Reject disabled TLS verification and ambiguous scope serialization.
- Keep OPA as the default adapter until a repository-owned PingAuthorize
  deployment package implements and passes the full allow/deny policy matrix.

## Task 27 — Repository-owned Ping product server profiles

Goal: start the local PingFederate and PingAuthorize products reproducibly from
repository-owned profile overlays instead of manual container mutation.

Acceptance criteria:

- Pin both product images by immutable digest.
- Mount profile overlays read-only at the supported `/opt/in` boundary.
- Build and test the PingFederate custom plugin before startup; do not commit
  generated JARs or SDK libraries.
- Install the PingAuthorize deployment package from a read-only mount through
  dsconfig during first setup.
- Keep credentials, licenses, private keys, generated certificates, discovery
  output, Terraform inputs, and Terraform state outside both profiles.
- Give PingAuthorize the stable DNS identity covered by its runtime
  certificate and attach it only to the local application bridge network.
- Add failure tests for unpinned images, embedded credentials, writable policy
  mounts, sample-policy fallback, malformed plugin artifacts, and unexpected
  network drivers.

## Task 28 — Clean-clone PingFederate profile bootstrap

Goal: build the repository-owned PingFederate profile from a clean checkout
without committing proprietary product SDK libraries.

Acceptance criteria:

- Extract only the four required public build-time JARs from the same
  digest-pinned PingFederate image used at runtime.
- Use a uniquely named, script-owned temporary container and remove only that
  exact container in cleanup.
- Reject missing, undersized, or non-JAR extraction results.
- Keep extracted SDK files ignored and never extract credentials, licenses,
  configuration, keys, or state.
- Automatically perform extraction only when a required build dependency is
  absent.

## Task 29 — Safe PingFederate bulk-profile export

Goal: export an existing local PingFederate configuration and run the approved
parameterizer without crossing secrets from generated state into the trusted
repository-owned profile.

Acceptance criteria:

- Read administrator credentials only from the ignored local environment file.
- Accept only the fixed local HTTPS PingFederate Admin API origin and validate
  its exact, current runtime certificate without disabling TLS verification.
- Bound request time and response size, and never include response bodies or
  credentials in errors.
- Run the converter by immutable image digest with no network, a read-only root
  filesystem, dropped capabilities, and a read-only parameterization config.
- Keep the raw export, extracted environment properties, converter log, and
  parameterized output under the ignored generated directory.
- Validate the parameterization config and resulting JSON, reject symlinked
  inputs/outputs, and never promote generated output into the startup profile
  automatically.
- Add failure tests for insecure TLS, embedded credentials, mutable images,
  unbounded export handling, writable converter inputs, and automatic profile
  promotion.

## Task 30 — Reviewed PingFederate application profile candidate

Goal: derive a reviewable application-only bulk profile candidate without
making bulk import a second configuration authority alongside Terraform.

Acceptance criteria:

- Select resource types and application object IDs through explicit allowlists.
- Reject unknown operations, resource types, application IDs, or duplicate
  singleton resources.
- Exclude administrator accounts, licenses, key pairs, certificates, system
  keys, server settings, and unrelated global OAuth settings.
- Convert encrypted password and OAuth client-secret fields to external
  substitutions; reject residual encrypted fields or literal credential data.
- Preserve Terraform as the authoritative writer and do not mount or import
  the generated candidate automatically.
- Add failure tests for an unexpected resource, unexpected client, residual
  encrypted value, literal secret, and attempted automatic import.

## Task 31 — Isolated clean-volume PingFederate bootstrap test

Goal: prove that the repository-owned profile and Terraform configuration can
recreate PingFederate without relying on the normal lab volume or state.

Acceptance criteria:

- Use cryptographically random, script-owned container, volume, and working
  directory names plus Docker-assigned loopback ports.
- Never stop, replace, connect to, or delete the normal workbench container or
  volume.
- Build the profile, wait for bounded health, and validate the exact runtime
  TLS certificate without disabling verification.
- Use an isolated ignored Terraform directory and state, apply the required
  scope and configuration, and verify a live token exchange plus its tampered
  actor-token failure case.
- Clean only exact test-owned resources and erase the isolated state by default.
- Add failure tests for fixed ports, shared state, insecure TLS, broad cleanup,
  unbounded waits, and ambiguous resource names.
