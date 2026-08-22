# Implementation Notes: Tasks 13–15

The gateway routes from SDK-standardized `Mcp-Method`/`Mcp-Name` headers to
fixed HTTPS targets and rejects unknown or ambiguous tools. It preserves the
immutable Authorization header and uses an injected timeout-bound downstream
client. Target URLs are trusted configuration, preventing caller-controlled
SSRF.

The demo server uses the official MCP Go SDK v1.7.0 in stateless Streamable
HTTP mode for protocol 2026-07-28. `system.whoami` returns only typed verified
identity metadata. The protected API consumes middleware context and never
parses JWTs.
