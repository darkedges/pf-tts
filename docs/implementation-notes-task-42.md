# Implementation Notes: Task 42

## Outcome

Task 42 adds a separate strict gateway constructor. It always wraps the chosen
OPA or PingAuthorize adapter with signed target/tool enforcement and requires
an audit sink plus a positive token bound. The legacy constructors and Bearer
forwarding path remain unchanged.

After route and policy approval, the strict gateway builds a downstream
request without copying Authorization, `Txn-Token`, Proxy-Authorization, or
connection credentials. It then obtains the immutable token from verified
middleware context and writes exactly one new `Txn-Token` field.

## Trust boundaries and failure cases

Inbound routing and headers are untrusted. Signed route mismatch, policy
denial, missing verified context, and any Authorization coexistence fail before
the downstream client runs. Even if strict middleware were accidentally
bypassed, the gateway rejects the legacy credential instead of stripping it
and continuing.

The positive test deliberately supplies a different untrusted inbound
`Txn-Token` header and proves downstream receives the unchanged token from
trusted context, not the inbound field. Failure tests prove no downstream call
or credential/token-bearing error occurs.

## Remaining work

No command constructs this gateway yet. The next task must add matching strict
MCP server and protected API handlers before the separately addressed strict
stack can be assembled and tested atomically.
