# Architecture

## Product objective

Provide trustworthy delegated identity for AI-agent initiated actions.

The security model must answer four different questions independently:

1. Which user initiated the action?
2. Which logical AI agent is acting?
3. Which runtime workload is making this network call?
4. Which transaction is this action part of?

## Target flow

```text
User
  |
  | OAuth access token
  v
AI Agent
  |
  | Fetch JWT-SVID(aud=PingFederate token exchange)
  v
SPIRE Agent
  |
  +--------------------+
                       |
AI Agent               |
  |                    |
  | RFC 8693           |
  | subject=user token |
  | actor=JWT-SVID     |
  v                    |
PingFederate <----------+
  |
  | short-lived transaction JWT
  v
MCP Gateway
  |
  | SPIFFE mTLS + same transaction JWT
  v
MCP Server
  |
  | SPIFFE mTLS + same transaction JWT
  v
Protected API
```

## Identity layers

### User identity

The subject token represents the authenticated end user.

Do not propagate the original subject token downstream after exchange.

### Logical agent identity

A stable identity such as:

```text
urn:agent:customer-support
```

It describes the approved logical agent definition.

It is not proof of which process is running.

### Agent instance identity

A unique ID for one runtime/execution of an agent.

Example:

```text
019...
```

Use a sortable UUID/ID implementation chosen by the codebase.

It is useful for observability and risk decisions but is not a replacement for workload attestation.

### Workload identity

SPIRE attests the workload and issues a SPIFFE identity such as:

```text
spiffe://example.org/agent/customer-support
```

Use:

- JWT-SVID when PingFederate needs a bearer-format actor token for RFC 8693 exchange.
- X.509-SVID for workload-to-workload mTLS.

### Transaction identity

Created once at the delegation boundary and preserved.

The transaction token is immutable.

Do not append each caller to the token as it travels.
The immediate caller is independently authenticated with SPIFFE mTLS.

## Why immutable transaction context

Mutating a JWT at every hop creates ambiguous trust:

- who is allowed to mutate it,
- who re-signs it,
- whether earlier context can be removed,
- whether a compromised middle service can forge later hops.

Instead:

```text
immutable delegated context + authenticated immediate caller
```

This yields two independent signals:

```text
Transaction JWT:
  user + agent + original workload + transaction + purpose

mTLS:
  the workload making this exact network connection
```

## Agent binding

A SPIFFE identity is mapped to a logical agent through trusted configuration/policy.

Example:

```yaml
agents:
  - id: urn:agent:customer-support
    allowed_spiffe_ids:
      - spiffe://example.org/agent/customer-support
```

The exchange caller must not be allowed to override that mapping by sending an arbitrary logical agent identifier.

For the MVP, derive `AgentID` server-side in the PingFederate policy or from a trusted mapping based on the verified actor SPIFFE ID.

## Boundaries

### PingFederate

Responsible for:

- RFC 8693 processing,
- validation of subject token,
- validation of actor JWT-SVID,
- workload-to-agent mapping,
- claim minimization,
- transaction-token issuance,
- transaction-token TTL and audience.

### SPIRE

Responsible for:

- workload attestation,
- SPIFFE identity issuance,
- JWT-SVID issuance,
- X.509-SVID issuance and rotation,
- workload trust bundles.

### MCP Gateway

Responsible for:

- verifying transaction JWT,
- verifying immediate SPIFFE caller,
- tool/server routing policy,
- preserving transaction context,
- downstream SPIFFE mTLS,
- audit correlation.

### MCP Server / API

Responsible for:

- verifying transaction JWT,
- authenticating immediate caller,
- enforcing target-specific authorization,
- preserving transaction ID in audit/trace context.

## MCP transport

For the remote MVP, prefer Streamable HTTP.

Keep identity/security middleware outside the MCP parser so protocol-version changes do not rewrite the trust model.

The 2026-07-28 MCP protocol is stateless at the protocol layer and introduces mandatory routing headers for modern Streamable HTTP requests. Use the chosen Go SDK's supported protocol revision and validate the corresponding standard headers rather than reimplementing protocol parsing in the security layer.

## Platform model

Linux and Windows are both targets.

Never hard-code a Unix socket assumption in the domain model.

Model the Workload API endpoint as configuration.

Examples:

```yaml
spiffe:
  endpoint: unix:///tmp/spire-agent/public/api.sock
```

Windows SPIRE supports a named-pipe Workload API. Keep the literal platform endpoint representation in the SPIRE adapter/config layer.

## Future architecture options

Not in MVP:

- interception proxy,
- Kubernetes sidecar/operator,
- dynamic policy engine,
- proof-of-possession transaction tokens,
- derived/downscoped transaction tokens at each service,
- trust-domain federation,
- per-tool token exchange,
- WIT-SVID.


## Self-contained SPIRE development topology

The repository owns a small development-only SPIRE topology:

```text
Docker Engine
   |
   +-- SPIRE Server
   |
   +-- SPIRE Agent
   |      |
   |      +-- Docker workload attestor
   |      +-- /run/spire/sockets/agent.sock
   |
   +-- demo-agent
   +-- mcp-gateway
   +-- demo-mcp-server
   +-- demo-api
```

The SPIRE Agent mounts the Docker Engine socket so it can resolve the container making a Workload API request and derive Docker selectors.

Workload registration uses labels:

```text
wai.workload=demo-agent
wai.workload=mcp-gateway
wai.workload=demo-mcp-server
wai.workload=demo-api
```

This produces distinct workload identities.

The Workload API socket is mounted into workload containers. Merely possessing filesystem access to the socket does not choose the SPIFFE ID; the SPIRE Agent performs workload attestation and matches selectors to registration entries.

### Development bootstrap

The local lab uses the SPIRE `join_token` NodeAttestor because it is simple and deterministic for developer environments.

Production guidance must replace it with an attestor appropriate to the runtime, such as cloud instance identity, Kubernetes PSAT, x509pop, TPM, or another deployment-specific mechanism.

### SPIRE version

The initial lab pins SPIRE `1.15.2`.

Keep the version in the Compose environment so upgrades are explicit and testable.
