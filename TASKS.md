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

## Task 32 — Generated PingFederate bootstrap trust material

Goal: replace the expired public sample certificate and keys inherited from the
upstream getting-started profile before PingFederate first accepts connections.

Acceptance criteria:

- Generate a 2048-bit RSA/SHA-256 self-signed local certificate with exact
  localhost and host.docker.internal SANs, a five-minute backdate, and at most
  30 days validity.
- Generate the PKCS#12 password, datastore password, and current/pending system
  keys with a CSPRNG; clear mutable random/key-export byte arrays.
- Write the upstream bulk-template variable names only to an ignored profile
  environment file using an atomic create and refuse overwrite.
- Require the administrator password through container orchestration rather
  than persisting it in the generated profile file.
- Mount the generated profile read-only and reject missing bootstrap material.
- Add failure tests for committed private material, weak keys, excessive
  validity, missing SANs, overwrite, plaintext administrator password, and
  mutable profile mounts.

## Task 33 — Transaction Tokens profile alignment review and migration plan

Goal: determine how closely the existing PingFederate, SPIRE, PingAuthorize,
MCP, and audit implementation can align with the Transaction Tokens model used
by CNCF Tokenetes and the current IETF Transaction Tokens draft, then produce a
phased plan that gets as close as the product boundaries safely allow.

This is a review and planning task. Do not change token issuance, validation,
transport, PingFederate configuration, or service behavior while completing
Task 33.

Acceptance criteria:

- Pin the review to an identified version and publication date of the IETF
  Transaction Tokens draft and record that it is not yet a final RFC. Compare
  the base profile separately from any agent-specific Transaction Tokens draft
  or actor profile so experimental extensions are not presented as base
  requirements.
- Use Tokenetes documentation and source as an implementation reference, but
  distinguish Tokenetes behavior, IETF normative requirements, and local
  design choices. Do not claim compatibility or conformance without evidence.
- Produce `docs/transaction-tokens-alignment-plan.md` with a requirement matrix
  covering the TTS trust-domain model, RFC 8693 request and response,
  requester authentication, subject-token processing, token type URNs,
  `typ: txntoken+jwt`, signing-key discovery and rotation, required and
  optional claims, lifetime, replay limits, replacement tokens, HTTP
  propagation, validation, policy input, privacy, audit, and error handling.
- Classify every requirement as implemented, partially implemented, missing,
  intentionally different, unsupported by the current product, or requiring
  investigation. For implemented items, cite exact repository files and tests.
  For product-dependent items, cite exact PingFederate or PingAuthorize
  documentation, discovered descriptors, or reproducible Admin API evidence.
- Map the current application claims to Transaction Tokens claims without
  collapsing `UserID`, `AgentID`, `AgentInstanceID`, `SPIFFEID`, or
  `TransactionID`. At minimum, review `sub`, `txn`, `scope`, `aud`, `req_wl`,
  `tctx`, and `rctx`, including which values are immutable, caller-derived,
  policy-derived, optional, sensitive, or prohibited.
- Review how PingFederate could act as the single logical Transaction Token
  Service for the local trust domain. Determine whether its token exchange,
  access-token manager, mapping expressions, token type response, and JOSE
  header controls can produce the required profile exactly. Never weaken
  subject-token, actor-token, issuer, audience, algorithm, key ID, time, or
  workload-to-agent validation to fit the profile.
- Review the SPIRE JWT-SVID actor token as an explicit agent integration.
  Explain whether it is requester authentication, an RFC 8693 `actor_token`,
  an agent-profile extension, or a local combination of those roles. Preserve
  the rule that PingFederate derives the logical `AgentID` from verified
  workload evidence rather than caller assertion.
- Review the audience migration from the current logical-resource audience to
  the Transaction Tokens trust-domain audience. Define how target, MCP server,
  tool, purpose, and scope remain narrowly authorized when `aud` no longer
  names only the gateway. Do not broaden effective authority as a side effect
  of this change.
- Review migration from bearer `Authorization` transport to the dedicated
  `Txn-Token` HTTP header. Cover gateway, MCP Streamable HTTP, MCP server, API,
  reverse proxy, CORS, header-size, duplicate-header, forwarding, redaction,
  and observability behavior. Reject multiple candidate transaction tokens and
  never silently prefer one header over another.
- Define an explicit compatibility strategy. Prefer an atomic local cutover or
  separately configured strict modes. Do not accept both the legacy token
  shape and Transaction Tokens shape ambiguously on the same protected route.
- Define the PingAuthorize and OPA policy-input migration using only verified,
  typed claims and authenticated immediate-caller identity. A policy engine
  remains an authorization decision point and does not replace Txn-Token or
  SPIFFE verification.
- Define privacy and logging rules for `tctx`, `rctx`, subject identity, actor
  identity, and decoded audit views. Raw subject tokens, actor tokens,
  Txn-Tokens, authorization headers, cookies, secrets, and private material
  remain prohibited from logs and durable audit payloads.
- Produce a phased implementation backlog with independently testable tasks,
  dependencies, rollback points, product capability blockers, and an explicit
  definition of done. Separate required profile conformance from optional
  agent extensions, replacement-token support, replay controls, and future
  proof of possession.
- Include a conformance test plan with positive and failure cases for token
  type, JOSE `typ`, issuer where configured, trust-domain audience, expiry,
  unique transaction ID, subject, scope, requester workload, exact claim
  schema, unknown key ID, disallowed algorithm, malformed context, duplicate
  headers, legacy bearer presentation, wrong SPIFFE caller, authority
  broadening, raw-token leakage, and immutable propagation through every hop.
- Identify any requirement that PingFederate or PingAuthorize cannot implement
  exactly. For each blocker, recommend one of: a narrowly scoped tested
  adapter, an upstream product enhancement, a documented non-conformance, or
  stopping the migration. Do not introduce an untrusted token rewriting proxy
  or custom signing service merely to make the conformance matrix appear
  complete.

Definition of done:

- The alignment plan is specific enough to split into ordered implementation
  tasks without further architectural guessing.
- Every security-sensitive gap states its trust boundary, failure behavior,
  required negative tests, and whether it changes effective authorization.
- The plan reports the closest safely achievable profile, the remaining
  non-conformances, and the evidence needed to resolve product-dependent
  unknowns.
- No runtime or infrastructure behavior changes as part of Task 33.

## Task 34 — Isolated PingFederate Transaction Tokens capability gate

Goal: determine, with reproducible sanitized evidence from the pinned
PingFederate 13.1 image, which draft-11 Transaction Tokens request, response,
and JWT-profile requirements PingFederate can support natively before any
runtime migration begins.

Acceptance criteria:

- Run only inside the random, script-owned clean-bootstrap container, volume,
  ports, certificate, and Terraform state. Never probe or change the normal
  workbench instance.
- Apply the existing trusted PingFederate configuration and prove the current
  subject-token, actor-token, and tampered-actor validation before running the
  capability probes.
- Send bounded form-encoded probes that independently test the Transaction
  Token requested type, trust-domain audience, `request_context`, and
  `request_details` while retaining the verified subject and SPIRE actor
  inputs. Do not weaken either token processor to obtain a successful result.
- Record only HTTP status, bounded OAuth error code, response token metadata,
  allowlisted JOSE header metadata, claim names, and presence/absence flags.
  Never record or print subject tokens, actor tokens, issued tokens, client
  secrets, passwords, authorization headers, response descriptions, raw
  response bodies, private material, or sensitive context values.
- Validate TLS with the exact isolated runtime certificate, use bounded network
  and subprocess timeouts, cap response size, require exact JSON object
  responses, and reject redirects, duplicate JSON keys, symlinked trust files,
  ambiguous SPIRE identities, and unexpected algorithms or key IDs.
- Treat rejection as capability evidence, not as a reason to relax validation.
  Distinguish unsupported requested type, unresolved audience, ignored context,
  malformed response, and inconclusive product behavior.
- Add failure tests for insecure TLS, normal-workbench targeting, token output,
  unbounded response handling, response-description logging, mutable shared
  state, broad cleanup, and a probe that omits the actor token.
- Produce `docs/implementation-notes-task-34.md` containing the exact pinned
  image, probe matrix, sanitized results, capability decision, trust boundaries,
  remaining unknowns, and recommendation for native support, product
  enhancement/documented non-conformance, a separately reviewed narrow
  non-signing adapter, or stopping the migration.
- Do not change application token issuance, verification, transport,
  PingAuthorize/OPA policy, or normal workbench configuration in Task 34.

## Task 35 — Strict Transaction Token domain model and verifier

Goal: model and verify the draft-11 inner Transaction Token JWT independently
of PingFederate and HTTP transport while the running application remains in
legacy mode.

Acceptance criteria:

- Add explicit `legacy-wai-jwt` and `ietf-txn-token-v11` profile modes and
  reject empty or unknown modes. Do not auto-detect token formats.
- Add a typed Transaction Token claim model for `iss`, `sub`, `aud`, `iat`,
  `exp`, `txn`, `scope`, `req_wl`, the bounded local `tctx.wai` profile, an
  optional bounded `rctx`, and optional `jti`. Keep user, logical agent, agent
  instance, requesting workload, and transaction identities distinct.
- Require a protected `typ=txntoken+jwt`, an explicitly allowlisted algorithm,
  exactly one non-empty `kid`, one compact JWS signature, and no unprotected
  JOSE fields.
- Require an allowlisted issuer, exact Trust Domain audience, bounded clock
  skew and lifetime, non-empty unique transaction and subject identifiers,
  allowlisted narrow scopes, exact requesting-workload/local-agent agreement,
  and a trusted SPIFFE workload-to-agent binding.
- Ignore unknown top-level claims, but strictly reject unknown or duplicate
  fields inside the local `tctx.wai` and `rctx` profiles. Bound the compact
  token, decoded payload, identifiers, scope count, and context values before
  returning typed claims.
- Resolve verification keys through an injected product-neutral boundary.
  Reject unknown or ambiguous key IDs and never select an algorithm from the
  token header outside the configured allowlist.
- Add failure tests for wrong or unprotected `typ`, disallowed algorithm,
  missing/unknown key ID, bad signature, issuer/audience/time/lifetime errors,
  duplicate JSON keys, malformed/oversized context, unknown local-profile
  fields, scope expansion, workload/agent conflict, and invalid profile mode.
- Do not connect the new verifier to middleware, issuance, transport,
  PingAuthorize, OPA, Terraform, or the normal workbench in Task 35.

## Task 36 — PingFederate strict inner Transaction Token profile

Goal: make the existing PingFederate-managed signer capable of emitting the
exact draft-11 inner JWT profile in an explicitly isolated mode without
claiming or changing the unsupported outer OAuth response semantics.

Acceptance criteria:

- Add an explicit plugin profile setting with only `legacy-wai-jwt` and
  `ietf-txn-token-v11`; reject missing or unknown values and never auto-detect.
- Preserve the existing legacy claim shape and `typ=at+jwt` when legacy mode
  is selected.
- In strict mode emit protected `typ=txntoken+jwt`, configured HTTPS `iss`,
  exact Trust Domain `aud`, numeric `iat`/`exp`, unique `txn`, bounded `sub`,
  fixed allowlisted narrow `scope`, verified actor workload as `req_wl`, and a
  bounded `tctx.wai` containing the trusted logical agent binding, minted agent
  instance, matching workload, fixed target, and fixed tool.
- Continue using only the PingFederate-managed signing key. Do not add another
  signer, rewrite a signed token, or copy untrusted request context/details.
- In strict mode derive target, tool, scope, AgentID, agent instance, and
  transaction ID from plugin configuration or trusted verified inputs. Reject
  a requested scope that does not exactly match the fixed configured scope.
- Add an isolated-only Terraform switch defaulting false. Normal state must
  continue to select the legacy profile, logical-resource audience, and
  current scope. Strict mode must select the Trust Domain and fixed narrow
  transaction context as one configuration unit.
- Add Java and repository failure tests for unknown profile, wrong scope,
  missing verified workload/subject, forged AgentID/workload conflicts,
  malformed context configuration, wrong JOSE type or audience, legacy-shape
  leakage into strict output, and accidental strict enablement in normal
  Terraform state.
- Extend the clean-bootstrap harness with a separate strict-inner-profile gate
  that independently verifies the signature and exact claim/header shape. Do
  not weaken the Task 34 capability conclusion: the outer response remains a
  bearer OAuth access-token response and is a documented non-conformance.
- Do not change application verification, `Authorization` transport,
  PingAuthorize/OPA input, or normal workbench runtime in Task 36.

## Task 37 — Narrow non-signing Transaction Token protocol adapter

Goal: provide the exact draft-11 outer token-exchange request and response
semantics that PingFederate 13.1 cannot expose natively, without adding a
signer, rewriting a token, or changing normal runtime wiring.

Acceptance criteria:

- Implement a separately wired HTTP handler only; do not add it to the normal
  application stack in this task.
- Require an authenticated SPIFFE mTLS requester through an injected verified
  peer-identity boundary. Reject absent, ambiguous, or invalid caller identity.
- Accept only POST, no query/cookie/Authorization credentials, exact
  form-encoded media type, bounded body, exact allowlisted fields, and exactly
  one value per field. Reject duplicates, unknown fields, empty values, and
  oversized subject or actor tokens.
- Require the RFC 8693 grant, access-token subject type, JWT actor type,
  Transaction Token requested type, exact Trust Domain audience, and one exact
  configured narrow scope.
- Translate only the unsupported outer requested type when calling the fixed
  injected PingFederate exchanger. Preserve subject and actor tokens in memory
  and never place them in URLs, logs, errors, or responses.
- Require PingFederate to return its known Bearer access-token response, then
  independently verify the returned strict inner JWT using Task 35. Require
  `req_wl` to equal the authenticated mTLS caller and require exact scope and
  Trust Domain agreement.
- Return the original compact PingFederate-signed token byte-for-byte with
  Transaction Token issued type, `token_type=N_A`, bounded positive expiry,
  `Cache-Control: no-store`, and no refresh token or response scope. Never
  sign, decode-and-resign, mutate, or derive another token.
- Return only allowlisted OAuth error codes without descriptions, upstream
  bodies, credentials, tokens, signing material, or verifier details.
- Add failure tests for method/media/query/cookie/Authorization misuse,
  duplicate or unknown form fields, missing actor, wrong token types/audience/
  scope, oversized input, failed upstream exchange, malformed outer response,
  invalid strict JWT, wrong requester workload, expiry inconsistency, token
  mutation, redirect-style behavior, and credential leakage.
- Add an ADR and threat-boundary notes. Keep the Task 34 native-product
  non-conformance explicit and do not claim end-to-end conformance until the
  adapter is deployed in an isolated SPIFFE mTLS stack and the Call Chain is
  atomically migrated.

## Task 38 — Isolated SPIFFE mTLS TTS adapter deployment gate

Goal: wire Task 37 as a separately addressed SPIFFE workload and prove the
exact outer protocol against the Task 36 isolated PingFederate profile before
any Call Chain migration.

Acceptance criteria:

- Add a dedicated adapter command with SPIFFE ID
  `spiffe://example.org/tts/adapter`; never reuse an agent, gateway, MCP, API,
  or audit identity.
- Obtain rotating X.509-SVID material only through the configured Workload API
  endpoint and require exact allowlisted requester SPIFFE IDs at TLS setup.
- Extract caller identity only after SPIFFE mTLS verification and pass it to
  the Task 37 handler. Do not trust forwarded identity headers.
- Add a bounded fixed-HTTPS PingFederate JWKS key resolver that rejects
  redirects, non-200 responses, oversized or duplicate-key JSON, missing or
  ambiguous `kid`, and empty key sets.
- Wire the fixed PingFederate exchanger, Task 35 strict verifier, exact Trust
  Domain, narrow scope, bounded timeouts/body/token/expiry, and no-store
  protocol handler through constructor validation and environment parsing.
- Add the distinct SPIRE Docker selector registration and an isolated-only
  container/service definition. Do not add the adapter to normal app-only or
  local-lab startup profiles.
- Add failure tests for missing/invalid configuration, wrong Workload API
  identity, untrusted TLS caller, rogue caller/actor mismatch, JWKS redirect,
  duplicate/oversized/ambiguous JWKS, unavailable PingFederate, exact outer
  response mismatch, token leakage, and broad/permissive peer policy.
- Add an isolated test that starts the strict PingFederate profile and adapter,
  makes a SPIFFE mTLS request from the approved demo-agent workload, verifies
  exact Transaction Token outer semantics and signature, then proves a wrong
  workload is rejected. Capture output and assert no raw token appears.
- Clean up only exact randomly named adapter/PingFederate containers, volumes,
  certificates, networks, and state. Keep normal workbench state unchanged.
- Do not begin `Txn-Token` Call Chain transport or policy migration in Task 38.

## Task 39 — Strict Txn-Token HTTP transport boundary

Goal: define the exact product-neutral HTTP field boundary used by the Phase E
Call Chain migration without enabling dual legacy/strict runtime parsing.

Acceptance criteria:

- Add a dedicated `Txn-Token` extractor that requires exactly one field value,
  a configured positive size bound, and one non-empty compact JWS value.
- Reject any request containing `Authorization`, including empty or duplicate
  values, when strict Transaction Token transport is selected.
- Reject missing, duplicate, comma-folded, whitespace/control-containing,
  malformed, and oversized `Txn-Token` values before verification.
- Add a propagation helper that writes exactly one `Txn-Token` value only to a
  clean destination header. Reject existing `Txn-Token` or `Authorization`
  fields rather than replacing or appending them.
- Return only a generic transport error and never include the token or header
  contents in errors.
- Add table-driven positive and failure tests, including legacy Bearer
  coexistence, duplicate values, proxy-style comma folding, malformed compact
  values, oversize, and propagation into a credential-bearing request.
- Document the trust boundary and rollback rule. Do not wire this boundary into
  the agent, gateway, MCP server, API, web application, policy adapters, or
  normal Compose profiles in Task 39.

## Task 40 — Strict Txn-Token verification middleware

Goal: convert one strict transported Transaction Token into typed verified
identity and signed route context while independently authenticating the
immediate SPIFFE caller.

Acceptance criteria:

- Add a separate constructor-built middleware that uses only the Task 39
  `Txn-Token` extractor and Task 35 strict verifier. Never fall back to or
  auto-detect the legacy Bearer middleware.
- Require an exact non-empty allowlist of immediate caller SPIFFE IDs and copy
  it during construction so later caller mutation cannot widen trust.
- Extract immediate caller identity only from verified TLS state, or from the
  existing explicitly configured SPIFFE-mTLS-already-verified boundary.
- Convert verified subject, logical agent, agent instance, requesting
  workload, transaction, and scopes into the existing typed identity context
  without collapsing them. Preserve a separately typed copy of the signed
  target and tool for policy enforcement.
- Put the immutable compact token into trusted context only after all token,
  identity, and caller checks pass.
- Produce only non-replayable token evidence for audit and fail closed if a
  configured verification-success audit sink cannot write.
- Add failure tests for Bearer transport, bad signature, missing/ambiguous/
  wrong caller, invalid typed identity, caller-allowlist mutation, audit
  failure, and any rejected request receiving token or signed-route context.
- Do not wire commands, policy adapters, downstream propagation, Compose, or
  normal workbench runtime in Task 40.

## Task 41 — Signed route enforcement and strict propagation

Goal: prevent a verified Transaction Token from being used for a different MCP
target/tool and propagate it downstream only through the strict HTTP field.

Acceptance criteria:

- Add an MCP authorizer decorator that requires the Task 40 signed route and
  exact target/tool agreement before invoking the configured OPA or
  PingAuthorize adapter.
- Reject missing signed route, empty route inputs, target mismatch, tool
  mismatch, and a missing underlying authorizer with a single generic denial.
- Preserve request cancellation and pass the existing typed verified identity
  unchanged to the underlying authorizer only after route agreement.
- Add a downstream propagation helper that obtains the immutable token only
  from trusted middleware context and writes it using the Task 39 strict
  `Txn-Token` helper.
- Require an existing signed route in the same trusted context before
  propagation. Reject nil requests, unverified tokens, existing Authorization
  or `Txn-Token` fields, malformed tokens, and non-positive bounds without
  mutating request headers.
- Never copy a token from an inbound header directly and never include token
  material in errors.
- Add table-driven failure tests for missing/mismatched route, underlying
  denial, cancellation, missing trusted token, credential-bearing destination,
  mutation on failure, and token leakage.
- Do not change gateway/server/API commands or normal Compose wiring in Task 41.

## Task 42 — Strict MCP gateway integration

Goal: integrate Tasks 39–41 through a separate gateway constructor without
changing the legacy gateway or any running command.

Acceptance criteria:

- Add a strict gateway constructor requiring an authorizer, audit sink, and
  positive token-size bound. Wrap authorization with signed target/tool
  enforcement so callers cannot omit it.
- Require verified identity, signed route, and immutable token context before
  forwarding. Reject any legacy Authorization field even if middleware was
  accidentally bypassed.
- Build downstream requests without generically copying Authorization,
  `Txn-Token`, Proxy-Authorization, or connection credentials.
- Propagate exactly one verified `Txn-Token` using Task 41 only after route and
  policy authorization succeeds.
- Keep the existing legacy constructors and Bearer behavior unchanged. Do not
  add auto-detection or a runtime mode switch.
- Add failure tests for route mismatch, policy denial, missing trusted context,
  legacy Authorization coexistence, invalid size bound, downstream not called
  on failure, and no credential/token leakage in errors.
- Add a positive test proving the downstream receives one unchanged
  `Txn-Token`, no Authorization field, and the expected MCP routing metadata.
- Do not wire commands, MCP server/API handlers, Compose, or the normal
  workbench in Task 42.

## Task 43 — Strict MCP server and protected API handlers

Goal: complete the unwired strict handler chain after the Task 42 gateway while
preserving exact signed route and immutable-token semantics.

Acceptance criteria:

- Add a separate strict demo MCP server constructor requiring the fixed HTTPS
  API client, endpoint, and positive token-size bound.
- Require exact signed target/tool agreement inside each MCP tool handler even
  when gateway authorization has already passed.
- Propagate the immutable token to the API only with Task 41 and never set or
  copy Authorization/Bearer credentials.
- Add a separate strict protected API handler requiring exact configured
  signed target/tool values, verified typed identity, verified immutable token,
  and no Authorization field.
- Return only safe transaction correlation data and never expose the compact
  token or signed context object.
- Reject missing/mismatched signed route, missing verified identity/token,
  legacy Authorization coexistence, unsafe downstream endpoint/client/bound,
  downstream rejection, and correlation mismatch.
- Prove downstream receives exactly one unchanged `Txn-Token` and no
  Authorization field; prove failures do not mutate headers or leak tokens.
- Keep legacy constructors and commands unchanged. Do not add Compose or
  runtime wiring in Task 43.

## Task 44 — Separately addressed strict Call Chain commands

Goal: assemble the strict gateway, MCP server, and API as separate command
targets without changing normal workbench identities, listeners, or startup.

Acceptance criteria:

- Add dedicated strict identities `spiffe://example.org/gateway/mcp-strict`,
  `spiffe://example.org/mcp/demo-strict`, and
  `spiffe://example.org/api/demo-strict`; do not reuse legacy service IDs.
- Add one strict verifier factory using the fixed PingFederate issuer/JWKS,
  explicit RS256 allowlist, Trust Domain `example.org`, narrow
  `mcp.system.whoami` scope, and trusted demo-agent workload binding.
- Construct every server with Task 40 middleware and an exact immediate-caller
  allowlist matching only the preceding strict hop.
- Construct every SPIFFE TLS server/client with the same exact peer ID as its
  middleware or downstream target. Never use trust-domain-wide or permissive
  authorization.
- Use distinct default listeners 8543, 8544, and 8545 and fixed HTTPS endpoint
  environment variables for the strict stack.
- Build the strict gateway only with Task 42, the strict MCP server only with
  Task 43, and the strict API only with Task 43.
- Add factory failure tests and repository tests proving distinct identities,
  exact peers, strict constructors, and absence from normal Compose profiles.
- Do not add Compose services, SPIRE registrations, an agent issuer client, or
  live startup in Task 44.

## Task 45 — Isolated strict Call Chain profile and agent

Goal: make the complete strict stack startable only through an isolated Compose
profile and provide an agent that obtains its token through the TTS adapter.

Acceptance criteria:

- Add exact SPIRE registrations and distinct Docker selectors for the three
  strict service identities. Reuse the existing demo-agent identity only for
  the same approved logical agent workload.
- Add an isolated `txn-token-call-chain` Compose profile containing the TTS
  adapter, strict gateway, strict MCP server, strict API, and strict demo agent.
  Do not add any strict service to `app-only` or `local-lab`.
- Mount a separate read-only strict OPA policy requiring the signed strict
  purpose, target, tool, workload, AgentID, and `mcp.system.whoami` scope.
- Add a strict demo agent that accepts an externally supplied user access token,
  obtains its actor JWT-SVID, calls only the fixed HTTPS TTS adapter with exact
  Transaction Token semantics, independently verifies the returned strict
  token, and calls only the strict gateway over exact SPIFFE mTLS.
- Send the gateway token only with one `Txn-Token` field. Never send
  Authorization, print response bodies, or log subject, actor, or transaction
  tokens.
- Bound all clients, bodies, responses, and token values; reject redirects,
  wrong adapter outer semantics, wrong signed requesting workload/route, and
  non-success gateway responses.
- Add unit/repository tests for missing token, malformed adapter response,
  wrong outer type, wrong strict claims, Bearer leakage, profile isolation,
  writable policy mounts, identity/selector mismatch, and embedded secrets.
- Do not run the live profile or change normal workbench state in Task 45.

## Task 46 — Live atomic strict Call Chain gate

Goal: prove the complete strict path against a fresh strict PingFederate profile
without changing or reusing normal workbench containers or state.

Acceptance criteria:

- Extend the exact-cleanup bootstrap harness with a distinct strict Call Chain
  switch that implies the Task 36 strict issuer and Task 38 adapter gates.
- Start the strict gateway, MCP server, and API on one randomly named isolated
  bridge network with exact randomly named containers and images.
- Exercise agent → adapter → gateway → MCP server → API using one unchanged
  PingFederate-signed Transaction Token and exact SPIFFE mTLS at every hop.
- Verify successful MCP/API transaction correlation without printing response
  bodies or any raw subject, actor, or transaction token.
- Prove the strict gateway rejects legacy Bearer transport and rejects a wrong
  SPIFFE workload during mTLS authentication.
- Capture strict service/probe output and reject JWT-shaped values, known
  credentials, Authorization values, or client secrets.
- Bound readiness, requests, responses, logs, and cleanup. Remove only exact
  random containers, images, network, certificate, Terraform work, and state.
- Record sanitized live evidence and confirm normal workbench containers and
  state are unchanged.

## Task 47 — Version-pinned Transaction Tokens conformance evidence

Goal: state precisely what the completed strict Call Chain implements against
the reviewed Transaction Tokens drafts without overstating interoperability or
PingFederate native support.

Acceptance criteria:

- Publish a concise conformance report pinned to
  `draft-ietf-oauth-transaction-tokens-11` and the separately evaluated
  `draft-oauth-transaction-tokens-for-agents-06`.
- Distinguish base-profile requirements, the local WAI agent extension,
  implementation hardening, and known product deviations.
- Link each implemented claim to repository code or repeatable test evidence.
- Explicitly record that PingFederate signs the inner token while the narrow
  adapter supplies the unsupported outer Transaction Token response semantics.
- State that the result is a closest-safe alignment profile, not native
  PingFederate support, IETF conformance certification, or Tokenetes
  compatibility.
- Add a repository test that fails if the report omits the pinned drafts,
  immutable `Txn-Token` transport, independent SPIFFE caller authentication,
  adapter deviation, or the non-conformance disclaimer.
- Do not implement the optional agent `act` extension, early invalidation,
  replacement tokens, replay infrastructure, proof of possession, or a normal
  workbench cutover in Task 47.

## Task 48 — Optional Helm and Argo CD deployment support

Goal: package the isolated strict Call Chain for Kubernetes GitOps deployment
without making Kubernetes a dependency of the local MVP.

Acceptance criteria:

- Add a Helm chart for the adapter, strict gateway, strict MCP server, and
  strict API with separate ServiceAccounts and Services.
- Obtain X.509-SVIDs only through the read-only SPIFFE CSI Workload API socket;
  do not mount Kubernetes API credentials into application pods.
- Reference existing PingFederate CA and OAuth credential Secrets without
  rendering or committing secret values.
- Optionally synchronize PingFederate CA, token-exchange client, and workbench
  OAuth values from HashiCorp Vault through Vault Secrets Operator using a
  namespace- and ServiceAccount-bound Kubernetes auth role. Never store a
  Vault token, AppRole secret, or application secret in Git or Helm values.
- Use non-root, read-only, no-capability containers, resource bounds, immutable
  image digest support, read-only policy configuration, and default-deny
  network policy.
- Provide exact SPIRE Controller Manager identity examples binding namespace,
  component, and actual Pod ServiceAccount. A mismatched ServiceAccount must
  not receive any application-accepted SPIFFE ID.
- Add a namespaced, least-privilege Argo CD project and a review-required
  Application template with no cluster-scoped or Secret permissions.
- Expose only the existing workbench Service at
  `workbench.ping.darkedges.com` for Cloudflare-terminated browser traffic.
  Keep the adapter, gateway, MCP server, and API free of public Ingress routes.
- Add tests and Helm rendering validation for missing configuration, embedded
  secrets, service-account token mounts, permissive pod security, mutable
  latest images, writable policy, and missing ServiceAccount identity binding.
- Do not deploy to a cluster, install CRDs, create Secrets, publish images, or
  change the local Docker workbench in Task 48.

## Task 49 — Isolated Kubernetes PingFederate 13.1 deployment contract

Goal: define the security and operational contract for a new Kubernetes-only
PingFederate 13.1 logical TTS without modifying the shared 12.3 deployment.

Acceptance criteria:

- Record the decision in ADR 0011 and keep `id.ping.darkedges.com`, its state,
  signing keys, clients, and workloads out of the new release's ownership.
- Use namespace `wai-pingfederate`, a derived runtime built from the
  digest-pinned official 13.1 product image, a distinct persistent `/opt/out`,
  and only the tested repository plugin JAR baked at the supported `/opt/in`
  boundary. Pin Ping's public Git server profile tag.
- Keep the administrator Service private. Permit browser access only to the
  minimum engine paths routed through `workbench.ping.darkedges.com`; never
  publish `/pf-admin-api`, the admin console, or port 9999.
- Define exact Vault records, ServiceAccounts, SPIFFE identities, network
  flows, persistence, readiness, backup, rollback, and image provenance.
- Treat PingFederate as the only signer. The TTS adapter may translate outer
  protocol semantics but may not sign or mutate the inner Transaction Token.
- Add failure tests for admin ingress, mutable product images, embedded
  credentials/bootstrap material, shared 12.3 resource references, and
  missing workload-to-AgentID bindings.
- Do not build images, create Vault records, or apply Kubernetes resources in
  Task 49.

## Task 50 — Secret-free PingFederate profile artifact image

Goal: package only repository-owned public startup artifacts needed by the
isolated 13.1 instance.

Acceptance criteria:

- Build and test the custom plugin against the matching pinned 13.1 SDK.
- Produce a minimal artifact image containing the reviewed plugin JAR and
  public profile hook only; do not redistribute the PingFederate product.
- Exclude `env_vars`, system keys, certificates, licenses, credentials,
  generated exports, Terraform files/state, and product SDK/runtime libraries.
- Pin the build inputs and publish by immutable digest from a clean Git tree.
- Add tests that enumerate the final artifact and fail on any unapproved file,
  private-key marker, credential name, symlink, or unexpected writable path.

## Task 51 — Explicit Vault bootstrap contract for isolated PingFederate

Goal: provide the isolated product and applications with reviewed secrets
without broadening the existing narrow local importer implicitly.

Acceptance criteria:

- Define separate KV v2 records for administrator password, Ping Identity
  DevOps credentials, bootstrap/system material, OAuth clients, and runtime CA.
- Require an explicit import switch for DevOps and bootstrap records; never
  import them through the default application-secret path.
- Bind Vault Kubernetes authentication to exact namespace and ServiceAccounts
  with the least-privilege policy and audience `vault`.
- Reject missing, duplicate, malformed, symlinked, oversized, or inconsistent
  inputs and create-only conflicts without printing values or response bodies.
- Add failure tests for wildcard policies, static Vault tokens, AppRole secrets,
  TLS verification bypass, partial input, and accidental secret rendering.

## Task 52 — Isolated PingFederate 13.1 Kubernetes runtime

Goal: start a durable, private-admin PingFederate 13.1 instance from the
reviewed profile and Vault inputs.

Acceptance criteria:

- Add a StatefulSet, persistent volume claim, private admin and engine
  Services, dedicated ServiceAccount, restrictive security context, resource
  bounds, probes, disruption behavior, and default-deny NetworkPolicy.
- Build the derived runtime from an exact two-file context (Dockerfile and
  tested plugin JAR), then inject bootstrap values only through read-only
  Vault-synchronized runtime references.
- Pin the official product base and derived runtime images by digest and accept
  the EULA explicitly without embedding image-download credentials.
- Never share `/opt/out`, credentials, signing material, Services, or selectors
  with the existing 12.3 release.
- Prove clean startup reports 13.1 and the exact reviewed plugin descriptors.
- Add failure tests for public admin exposure, mutable images, writable secret
  mounts, absent persistence, unsafe probes, and cross-namespace selection.

## Task 53 — Private Terraform configuration gate for PingFederate 13.1

Goal: configure the isolated logical TTS only after runtime and descriptor
attestation succeeds.

Acceptance criteria:

- Reach port 9999 only through a bounded local port-forward or equivalent
  private administrative channel; never create an admin Ingress.
- Verify exact product version and plugin class names before plan or apply.
- Configure the strict subject/actor processors, TEPP, ATM, scope, OAuth
  clients, signing configuration, and exact demo/workbench workload bindings.
- Keep administrator and OAuth credentials out of arguments, output, plans,
  committed tfvars, and shared state; document protected state handling.
- Reject wrong version, missing actor processor, unknown descriptor, forged
  AgentID, wrong SPIFFE ID, missing audience, and encrypted/plaintext drift
  ambiguity without weakening validation.

## Task 54 — Strict Kubernetes workbench and audit integration

Goal: deploy the authenticated UI on the strict Transaction Token path with a
complete selectable audit trail.

Acceptance criteria:

- Give workbench and audit collector distinct ServiceAccounts and exact SPIFFE
  IDs; bind workbench only to `urn:agent:web-app` in trusted TTS configuration.
- Replace Docker-only OIDC backchannel behavior with fixed Kubernetes-safe
  endpoints and exact SPIFFE peers for adapter, gateway, and audit collector.
- Deploy the audit collector and configure every strict hop to submit bounded,
  redacted evidence while preserving one immutable Transaction ID/token.
- Store sessions only in bounded memory for this lab, use secure host cookies,
  PKCE, state, nonce, exact redirect URI, CSRF origin checks, and no refresh
  tokens.
- Add failure tests for demo/workbench identity substitution, raw-token audit,
  legacy gateway use, unapproved tool/purpose, wrong audit caller, and unsafe
  OIDC endpoint rewriting.

## Task 55 — Immutable application publication and deployment values

Goal: publish every repository-owned runtime artifact and create a fully
digest-pinned deployment input.

Acceptance criteria:

- Publish strict services, workbench, audit collector, and the derived
  PingFederate runtime from a clean commit for Linux amd64/arm64 where supported.
- Record registry manifest digests and use digests, not tags, in reviewed Helm
  values; never commit registry tokens or Docker credential files.
- Render and lint the complete chart with no Secret values and no unresolved
  required configuration.
- Add failure tests for dirty publication, missing platform, mutable tag,
  digest mismatch, missing image, and secret-bearing Docker context.

## Task 56 — Single-hostname workbench and PingFederate engine routing

Goal: expose only the browser-required surface through Cloudflare and nginx.

Acceptance criteria:

- Keep `workbench.ping.darkedges.com` as the only new public hostname.
- Route application paths to workbench and an explicit allowlist of required
  `/as`, `/pf`, and `/idp` engine paths to the isolated engine Service.
- Deny admin API/console paths and keep adapter, gateway, MCP, API, audit, Vault,
  SPIRE, and port 9999 private.
- Preserve external HTTPS origin and exact redirect URI without trusting
  Cloudflare identity headers as user or workload identity.
- Add rendering and live negative tests proving forbidden paths and hosts do
  not reach PingFederate or internal services.

## Task 57 — Kubernetes end-to-end deployment and rollback gate

Goal: prove and hand over the complete isolated Kubernetes Transaction Token
solution with repeatable rollback.

Acceptance criteria:

- Pass browser login, strict exchange, immutable-token call chain, and
  correlated audit evidence through API completion.
- Fail forged logical AgentID, wrong SPIFFE workload/caller, wrong audience,
  expired token, unapproved target/tool, legacy Bearer transport, and a stolen
  token presented over the wrong mTLS identity.
- Scan logs and rendered/live resources for raw tokens, credentials, private
  keys, unsafe public Services, and unexpected identity entries.
- Record pinned versions/digests, sanitized evidence, backup/restore steps,
  readiness observations, and exact rollback commands.
- Rollback must remove only the isolated WAI releases/resources and must not
  mutate or interrupt the existing PingFederate 12.3 deployment.
