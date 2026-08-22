# Implementation Notes: Tasks 16–17

The agent workflow obtains its actor identity from SPIRE, exchanges the original
user token, and propagates only the resulting transaction token. Logical Agent
ID is not an exchange input. Spoof and expired-token modes therefore fail
locally instead of weakening issuer or binding validation. IDs combine time
ordering with cryptographic randomness.

Audit events have a fixed typed schema with no credential fields. JSON output
adds timestamps and is concurrency-safe. Tests assert common credential field
names and bearer material cannot appear in serialized events.

The agent independently verifies the PingFederate-issued transaction JWT
before forwarding or auditing it. Signature, issuer, audience, time, purpose,
logical AgentID, and workload SPIFFE ID must match trusted configuration. The
live lab requires one transaction ID across structured agent, gateway, MCP
server, and API events. Audit-sink failure and forged verified bindings fail
closed.
