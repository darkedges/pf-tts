# UI-07 implementation notes

## Acceptance criteria

- Compose and SPIRE registration include distinct `web-app` and
  `audit-collector` workloads.
- A live browser signs in through PingFederate, invokes the allowlisted
  `system.whoami` operation, displays one immutable transaction identifier
  across web app, gateway, MCP server, and API evidence, selects the exact
  audit record requested, and logs out.
- Forged state, unauthenticated invocation, CSRF, cross-user audit access,
  direct service calls, ambiguous caller identity, and credential-shaped audit
  data fail closed.
- Local HTTPS certificates are explicitly validated and trusted; neither the
  browser nor service clients disable certificate validation.
- Go formatting/tests/vet, Terraform formatting/validation, live lab tests,
  and Windows/Linux command builds pass.

## Trust boundaries and failure tests

The browser trusts two exact development-only self-signed leaves: the
30-day `localhost` web certificate and the current PingFederate runtime leaf.
The trust scripts reject a PingFederate CA, non-self-signed certificate,
expired certificate, ambiguous chain, or missing required DNS binding. Tests
inspect the scripts for these fail-closed controls and prohibit certificate
validation bypasses.

The audit collector receives requests only through a SPIFFE-authenticated mTLS
listener. Because SPIFFE performs peer verification in the listener rather
than Go's conventional CA-chain verifier, caller extraction uses the explicit
already-verified mTLS path. Missing, malformed, ambiguous, and unapproved
SPIFFE identities remain rejected and are covered by tests. Rejection logs use
fixed reason codes and never include request content.

The browser BFF retains PingFederate's exact public issuer and TLS hostname.
Its container-only backchannel mapping accepts only `localhost:9031` and maps
that address to Docker's host gateway without changing hostname, issuer, or
certificate validation. An attacker-controlled address and an unbounded HTTP
client are rejected by tests.

The audit UI includes the transaction identifier in each event's accessible
name and does not rebuild an unchanged event list during polling. This prevents
selection races between repeated event names. Logout clears rendered result
and audit detail nodes in addition to invalidating the opaque server session.

## Live result

The browser issued transaction `93294597-5eec-4c37-9ddc-cb2ca0ea8a81` as
`urn:agent:web-app`. Five correlated records were observed: exchange at the
web app, gateway verification, MCP authorization, MCP-server verification, and
API verification. Selecting hop five returned the same transaction, target
`demo-api`, transaction workload `spiffe://example.org/agent/web-app`, and
immediate caller `spiffe://example.org/mcp/demo`. Logout invalidated the
session; the subsequent DOM-clearing defect found during the live test was
fixed and regression-checked.
