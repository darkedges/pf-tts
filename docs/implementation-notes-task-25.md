# Implementation Notes: Task 25

Acceptance criteria: compile a bounded repository-owned Rego policy at gateway
startup; evaluate it in-process with the request context; accept only one
boolean `data.wai.authz.allow` result; and deny false, undefined, malformed,
cancelled, timed-out, or failed evaluation. The container policy mount must be
read-only, OPA network built-ins must be unavailable, and the authorizer
interface must remain replaceable by a future PingAuthorize adapter.

The trust boundary begins after transaction JWT and SPIFFE mTLS verification.
OPA receives typed copies of the verified logical AgentID, agent instance ID,
original workload SPIFFE ID, transaction purpose and scopes, plus the target
and tool selected by the gateway's static route table. It never receives raw
tokens, request-supplied identity fields, tool arguments, or arbitrary headers.

The Rego module is trusted deployment configuration. It is loaded once from a
read-only mount, limited to 1 MiB, and compiled before the gateway listens.
Startup fails on missing or invalid policy. `http.send` and
`net.lookup_ip_addr` are removed from OPA capabilities so policy evaluation
cannot create an outbound network trust path. Evaluation has a 100 ms deadline
and request cancellation is fail-closed.

Failure tests cover a forged logical agent, undefined and non-boolean results,
cancelled evaluation, invalid Rego, and a policy attempting `http.send`. These
tests preserve strict identity validation; none changes JWT, audience, issuer,
SPIFFE caller, or route verification behavior.
