# Implementation Notes: Tasks 16–17

The agent workflow obtains its actor identity from SPIRE, exchanges the original
user token, and propagates only the resulting transaction token. Logical Agent
ID is not an exchange input. Spoof and expired-token modes therefore fail
locally instead of weakening issuer or binding validation. IDs combine time
ordering with cryptographic randomness.

Audit events have a fixed typed schema with no credential fields. JSON output
adds timestamps and is concurrency-safe. Tests assert common credential field
names and bearer material cannot appear in serialized events.
