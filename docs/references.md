# External references to verify during implementation

These are design inputs, not copied implementation requirements.

## PingFederate

PingFederate 13.x supports the OAuth 2.0 Token Exchange grant defined by RFC 8693. A token exchange includes a required subject token and can include an actor token. Token Exchange Processor Policies select token processors and map validated token attributes into the issued result.

Important implementation checks:

- confirm the exact JWT actor token type identifier accepted by the deployed PingFederate version,
- configure the TEPP and JWT token processor against SPIRE trust material,
- verify output access-token claim mapping and TTL,
- verify the deployed token endpoint and JWKS endpoint.

## SPIFFE / SPIRE

The SPIFFE Workload API supports JWT-SVID and X.509-SVID profiles.

The Go SPIFFE library provides high-level support for:

- obtaining JWT-SVIDs,
- obtaining rotating X.509-SVID sources,
- validating identities,
- SPIFFE-based mTLS.

SPIRE Agent supports a Workload API named pipe on Windows as well as Unix-domain sockets on Unix-like systems.

## MCP

The 2026-07-28 MCP specification makes the modern protocol stateless at the protocol layer and adds header-based routing information for Streamable HTTP.

Use a maintained MCP SDK/library rather than implementing the wire protocol from scratch.
