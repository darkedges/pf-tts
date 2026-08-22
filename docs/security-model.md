# Security Model

## Core authorization statement

A request is not trusted because it has a valid transaction JWT alone.

For protected network hops, authorize from the conjunction of:

```text
verified transaction context
AND
verified immediate SPIFFE caller
AND
target policy
```

## Example

A transaction JWT says:

```text
User: user-123
Agent: urn:agent:customer-support
Original workload: spiffe://example.org/agent/customer-support
Transaction: tx-123
Audience: urn:wai:mcp-gateway
```

The network connection additionally proves:

```text
Immediate caller: spiffe://example.org/agent/customer-support
```

At a later hop:

```text
Same transaction JWT
Immediate caller: spiffe://example.org/mcp/customer-server
```

That allows the protected API to reject the original agent calling the API directly if only the MCP server is authorized as its caller.

## Threats to test explicitly

### Forged logical agent

Attacker sends `agent_id=trusted-agent`.

Mitigation:
derive AgentID from verified SPIFFE actor identity.

### Stolen transaction token

Attacker obtains a transaction JWT.

Mitigations:
short TTL, strict audience, TLS, immediate-caller SPIFFE policy, optional replay/PoP later.

### Confused deputy

Approved agent tries to use a valid token against an unintended MCP server/API.

Mitigations:
audience restriction, target routing policy, service authorization.

### Compromised intermediary

MCP gateway/server is compromised.

Mitigations:
immutable transaction context, distinct downstream caller identity, minimum audience/scope, audit, target service policy.

### Token leakage

Mitigations:
central redaction, form-body exchange, no query tokens, no token values in errors.

## Replay

The MVP is bearer-token based and therefore cannot completely eliminate replay if a token and a valid network position are compromised.

Mitigate with:

- 15–30 second transaction TTL,
- narrow audience,
- TLS,
- immediate caller SPIFFE identity,
- optional `jti` monitoring.

Do not add a distributed replay cache without first defining the replay threat and operational costs.

Future proof-of-possession can cryptographically bind a transaction token to a workload key.

## Logging

Safe fields:

- transaction ID,
- user stable identifier where policy permits,
- logical agent ID,
- SPIFFE IDs,
- target,
- decision,
- reason code,
- expiry timestamp.

Never log:

- subject token,
- actor JWT-SVID,
- transaction token,
- authorization header,
- private key,
- refresh token,
- OAuth client secret.
