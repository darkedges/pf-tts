# Implementation Notes: Task 26

## Acceptance criteria

The PingAuthorize adapter receives only the gateway's typed identity context
created after transaction JWT and SPIFFE mTLS verification. It sends that
context to a fixed HTTPS JSON PDP endpoint with bounded request time and
response size. A result is allowed only when the response is structurally
complete, has policy status `OKAY`, and contains consistent `PERMIT` and
`authorised: true` values with no unfulfilled obligatory statement.

Failure tests cover denial, contradictory or missing decisions, unknown JSON
fields, policy errors, unfulfilled obligations, oversized responses, incorrect
content types, upstream failures, cancellation, timeout, unsafe endpoints,
disabled TLS verification, and ambiguous scope encoding.

## Trust boundary

The browser and MCP caller cannot supply PingAuthorize decision attributes.
The gateway constructs them from the verified request identity and its trusted
route. PingAuthorize is a remote decision point, not an identity verifier; it
cannot replace JWT signature, issuer, audience, time, logical-agent/workload,
or immediate-caller verification.

The repository owns `deploy/pingauthorize/policies/wai-mcp-authorization.deploymentpackage`.
Its single permit is guarded by an `AND` over exact logical-agent, workload,
immediate-caller, purpose, scope, target, and tool comparisons and is targeted
to `WAI / WAI MCP / Invoke`. Package-graph tests reject changed or disconnected
bindings before deployment. The live local server returned `PERMIT` for the
exact tuple and `NOT_APPLICABLE` for a forged logical agent over
certificate-validated HTTPS.

The local gateway now uses PingAuthorize at the stable Docker DNS identity
`pingauthorize-wai`. The runtime certificate exporter accepts only the
repository-owned container identity, verifies certificate validity and the
exact DNS SAN, and writes only the public certificate into the ignored
generated directory. Compose mounts that trust anchor read-only. TLS
`ServerName` overrides and disabled hostname verification remain prohibited.

SPIRE JWT authorities can overlap during normal signing-key rotation. The
export path trusts one or more keys only when every bundle entry is explicitly
marked as a SPIRE JWT-SVID authority, has a unique non-empty key ID, and is an
EC P-256 key. The generated PingFederate inputs independently require unique
EC P-256 ES256 signing keys with complete public coordinates. Empty,
duplicate, malformed, or algorithm-conflicting key sets fail before apply.
This preserves verification across rotation without dynamically trusting the
JWT header algorithm or accepting an unknown key ID.

The browser end-to-end check completed through PingFederate, PingAuthorize,
the MCP gateway, MCP server, and demo API. PingAuthorize recorded `PERMIT` from
deployment package `1ca3f398-1ba9-4169-a576-7fac52b286db`; the UI displayed the
same verified transaction ID across five audit events.

The JSON contract follows the PingAuthorize 11.1 JSON PDP individual endpoint
at `/governance-engine`. The running 11.1 image returns the response property
`authorised`; the adapter deliberately rejects alternate or missing spellings
instead of guessing.
