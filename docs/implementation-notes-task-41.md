# Implementation Notes: Task 41

## Outcome

Task 41 adds two unwired Phase E boundaries. The signed-route authorizer
requires the requested MCP target and tool to exactly equal verified
`tctx.wai.target` and `tctx.wai.tool` before invoking OPA or PingAuthorize. The
propagation helper obtains the immutable compact token only from trusted
middleware context and writes exactly one `Txn-Token` field to a clean request.

## Trust boundaries

MCP routing values remain request-controlled until compared with the signed
route. A successful token signature alone cannot authorize another target or
tool. Policy evaluation occurs only after that signed agreement and receives
the existing typed identity unchanged.

Downstream request headers are a separate boundary. Existing Authorization or
`Txn-Token` fields cause denial rather than replacement. The helper never reads
the raw inbound HTTP field; it accepts only the token placed in context after
Task 40 verification and requires the signed route to be present in that same
trusted context.

## Failure behavior

All route and propagation failures return one generic error without policy
details or token material. Tests cover missing and mismatched routes,
underlying denial, cancellation, missing trusted context, malformed trusted
token, existing credentials, non-positive bounds, nil requests, mutation on
failure, and leakage.

## Remaining work

No command or runtime handler uses these boundaries yet. The next task must
construct a separately addressed strict gateway/server/API stack that uses
them together; it must not retrofit one hop at a time into the normal legacy
workbench.
