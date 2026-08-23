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

OPA remains the default adapter until the Docker gateway can reach a
PingAuthorize endpoint whose certificate contains the stable container DNS
name. The current development container certificate is valid for `localhost`,
its container ID, and loopback addresses, but not the `pingauthorize` service
name. Overriding TLS `ServerName` or disabling hostname validation would weaken
the trust boundary and is not permitted.

The JSON contract follows the PingAuthorize 11.1 JSON PDP individual endpoint
at `/governance-engine`. The running 11.1 image returns the response property
`authorised`; the adapter deliberately rejects alternate or missing spellings
instead of guessing.
