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

The running `getting-started/pingauthorize` profile is intentionally not wired
into the gateway. Its sample policy currently permits the test request and
returns an unfulfilled obligation. Activating that profile would weaken the
repository policy. OPA remains the default until a repository-owned deployment
package passes the same allow and failure matrix.

The JSON contract follows the PingAuthorize 11.1 JSON PDP individual endpoint
at `/governance-engine`. The running 11.1 image returns the response property
`authorised`; the adapter deliberately rejects alternate or missing spellings
instead of guessing.
