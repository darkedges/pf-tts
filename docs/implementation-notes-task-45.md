# Implementation Notes: Task 45

## Outcome

Task 45 adds the opt-in `txn-token-call-chain` Compose profile. It contains the
TTS adapter, strict gateway, strict MCP server, strict API, and strict agent.
None of these services is part of `app-only` or `local-lab`.

SPIRE registrations give the three strict services distinct IDs and Docker
selectors. The strict agent deliberately reuses `spiffe://example.org/agent/demo`
and the existing `demo-agent` selector because it is the same approved logical
agent workload, not a new service identity.

## Agent and policy trust boundaries

The strict agent accepts the user access token only from external environment
injection. It obtains the actor JWT-SVID from SPIRE, sends both credentials only
in the bounded form body to the fixed mTLS TTS adapter, requires exact outer
Transaction Token semantics, and independently verifies the strict signed
claims before invoking the gateway.

The gateway receives exactly one `Txn-Token` field over mTLS. The agent never
sets Authorization, prints response bodies, or includes subject, actor, or
transaction tokens in errors. Adapter and gateway peers are exact SPIFFE IDs.

The separate read-only OPA policy allows only the demo AgentID/workload, signed
`demo:system.whoami` purpose, exact target/tool, and the single
`mcp.system.whoami` scope.

## Failure tests and remaining work

Tests reject missing configuration, malformed/duplicate/unknown/oversized
adapter responses, wrong outer semantics, wrong verified bindings, credential
leakage, unsafe profile placement, writable policy wiring, and registration
count/selector drift.

The profile has not been started. A live gate still needs a fresh strict
PingFederate profile, a user subject token, exact startup/readiness handling,
positive end-to-end correlation, wrong-workload and Bearer rejection, captured
log scanning, and exact cleanup before any normal-workbench migration.
