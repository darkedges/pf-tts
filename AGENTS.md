# AGENTS.md

## Mission

Implement a portable Go security product that allows an AI agent to act on behalf of an authenticated user while preserving and verifying:

1. the user identity,
2. the logical AI agent identity,
3. the runtime workload identity,
4. the transaction identity and purpose,
5. the immediate caller at each network hop.

The MVP uses:

- Go,
- PingFederate as OAuth authorization server and transaction-token issuer,
- RFC 8693 OAuth 2.0 Token Exchange,
- a self-contained SPIRE Server/Agent lab for development,
- SPIRE / SPIFFE Workload API,
- JWT-SVID for agent-to-PingFederate actor authentication,
- X.509-SVID + mTLS for workload-to-workload authentication,
- MCP Streamable HTTP as the primary remote MCP transport,
- a short-lived PingFederate-issued JWT as the immutable transaction context.

## Architecture invariant

Never collapse these identities into one field:

- UserID
- AgentID
- AgentInstanceID
- SPIFFEID
- TransactionID

`AgentID` is a logical application identity.
`SPIFFEID` is a cryptographically attested runtime identity.

They are related by trusted configuration or policy, not by caller assertion.

## Security invariants

These rules are mandatory.

1. Never trust an `agent_id`, `workload_id`, `caller`, `user_id`, or equivalent identity field supplied by an untrusted request without cryptographic verification.
2. Never parse JWT claims before signature and issuer validation and then use those claims for authorization.
3. Never dynamically trust a JWT algorithm based only on the token header.
4. Never log raw access tokens, JWT-SVIDs, transaction tokens, client secrets, private keys, refresh tokens, authorization codes, cookies, or mTLS private material.
5. Token audiences are mandatory and must be checked.
6. Issuers are allowlisted.
7. Clock skew is small and configurable.
8. Transaction tokens are short-lived and do not become session tokens.
9. The transaction token remains immutable across the call chain.
10. Immediate caller identity comes from authenticated SPIFFE mTLS, not from mutating the transaction token.
11. The original user's access token must not be propagated to MCP servers or downstream APIs after token exchange.
12. A workload cannot become another logical agent by sending a different `AgentID`.
13. Error messages must not leak bearer tokens or signing material.
14. Reject on ambiguity: multiple candidate workload identities, unknown key IDs, unknown issuers, missing audience, missing required bindings, or conflicting identity claims.

## MVP trust flow

0. For local development, start the repository-owned SPIRE lab. The lab bootstraps a SPIRE Server and Agent, then registers workload entries using Docker workload selectors. Production deployments may replace the lab SPIRE configuration without changing core code.
1. The user authenticates and obtains an OAuth access token from the configured user-facing OAuth flow.
2. The AI agent receives the user access token.
3. The agent obtains a JWT-SVID from the SPIRE Workload API with an audience dedicated to the PingFederate token-exchange integration.
4. The agent performs RFC 8693 token exchange against PingFederate:
   - `subject_token` = user access token
   - `subject_token_type` = access token
   - `actor_token` = agent JWT-SVID
   - `actor_token_type` = JWT
   - `audience` = MCP gateway or a configured logical resource
5. PingFederate validates both tokens through a Token Exchange Processor Policy (TEPP), maps the SPIFFE actor identity to an allowed logical `AgentID`, and issues a short-lived transaction JWT.
6. The agent calls the MCP gateway with the transaction JWT.
7. The agent and gateway use SPIFFE X.509-SVIDs for mTLS.
8. The gateway validates:
   - PingFederate signature,
   - issuer,
   - audience,
   - time claims,
   - required transaction claims,
   - logical agent/workload binding,
   - immediate SPIFFE caller identity.
9. The gateway forwards the immutable transaction JWT to an allowed MCP server over SPIFFE mTLS.
10. Downstream services repeat the same pattern.
11. Structured audit logs correlate all hops by `TransactionID`.

## Desired transaction token claims

Keep claims small and strongly typed.

Example conceptual form:

```json
{
  "iss": "https://ping.example.invalid",
  "sub": "user-123",
  "aud": "mcp-gateway",
  "scope": "mcp:invoke",
  "agent": {
    "id": "urn:agent:customer-support",
    "instance_id": "019..."
  },
  "workload": {
    "id": "spiffe://example.org/agent/customer-support"
  },
  "txn": {
    "id": "019...",
    "purpose": "read-customer-record"
  },
  "iat": 0,
  "exp": 0,
  "jti": "019..."
}
```

Do not blindly copy arbitrary claims from the subject or actor token into the result.

## Project rules

- Prefer standard library and narrowly scoped dependencies.
- Hide external products behind small adapters.
- Core domain packages must not import PingFederate-specific or SPIRE-specific implementation packages.
- Kubernetes must never be required for the MVP.
- Linux and Windows must both be considered at API boundaries.
- Keep the SPIFFE endpoint configurable. Do not scatter Unix socket paths through code.
- Use dependency injection through constructors, not package globals.
- Use `context.Context` for all I/O operations.
- Set network timeouts explicitly.
- Make HTTP clients injectable/testable.
- Prefer table-driven tests in Go.
- Run `go test ./...` after each task.
- Run static analysis before considering a task complete.
- Do not add a new abstraction unless a second implementation is known or it isolates an external boundary.
- Write ADRs for security-significant design changes.

## Repository layout

```text
cmd/
  demo-agent/
  mcp-gateway/
  demo-mcp-server/
  demo-api/

pkg/
  identity/
  spiffe/
  pingfederate/
  transaction/
  middleware/
  mcp/
  audit/

internal/
  config/
  verification/

deploy/
  docker/
  spire/
  pingfederate/

docs/
tests/
```

## Definition of done for the MVP

A local or lab environment must demonstrate:

- PASS: valid user + approved agent workload.
- FAIL: valid user + forged logical AgentID.
- FAIL: valid user + wrong SPIFFE workload.
- FAIL: expired transaction token.
- FAIL: wrong audience.
- FAIL: unapproved MCP target.
- FAIL: valid/stolen transaction token presented over the wrong SPIFFE mTLS identity where caller binding is required.
- PASS: one TransactionID is visible in structured logs across agent → gateway → MCP server → API.
- PASS: no raw tokens appear in logs.
- PASS: `go test ./...`.
- PASS: Linux build.
- PASS: Windows build for platform-neutral packages and supported command targets.

## Codex working method

Work through `TASKS.md` in order.

For each task:

1. restate the acceptance criteria in the implementation notes,
2. inspect existing packages before creating new ones,
3. implement the smallest complete change,
4. add tests,
5. run formatting,
6. run `go test ./...`,
7. report files changed and security-relevant decisions,
8. stop if an assumption would weaken token validation or identity binding.

Do not implement future phases speculatively.


## Local SPIRE lab rules

The repository includes `deploy/spire/` and `scripts/spire-*.sh`.

The lab is allowed to use a join-token node attestor because it is explicitly development-only. Do not promote this bootstrap method as the default production deployment.

Workload identity registration must use externally observed selectors. For the Docker lab use labels such as:

```text
docker:label:wai.workload:demo-agent
```

Never issue all demo workloads the same SPIFFE ID.

The lab trust domain is:

```text
example.org
```

For the pinned SPIRE 1.15.2 join-token attestor, the parent node identity is
generated by SPIRE in its reserved agent namespace and has this pattern:

```text
spiffe://example.org/spire/agent/join_token/<one-time-token-id>
```

Do not attempt to force a fixed identity under `/spire/agent/`; SPIRE owns that
namespace and rejects caller-assigned IDs there. The bootstrap may persist the
derived, non-secret agent ID in gitignored generated material for registration,
but it must never persist the join token. Registration must reject missing,
malformed, or ambiguous candidate parent identities.

Registered workload identities are:

```text
spiffe://example.org/agent/demo
spiffe://example.org/gateway/mcp
spiffe://example.org/mcp/demo
spiffe://example.org/api/demo
```
