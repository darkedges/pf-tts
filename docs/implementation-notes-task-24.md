# Implementation Notes: Task 24

Acceptance criteria: authorize MCP tool calls only when trusted policy matches
the verified logical AgentID, original workload SPIFFE ID, transaction purpose,
required scopes, fixed MCP target, and tool. Policy parsing must reject unknown,
empty, incomplete, or ambiguous configuration. Missing verified identity and
all tuple conflicts deny. Decisions must be audited without credentials.

The gateway loads `config/authorization.json` from a read-only container mount.
This file is inside the deployment trust boundary; request headers and tool
arguments cannot add or modify rules. Middleware first verifies the
PingFederate signature, issuer, audience, times, required claims, and SPIFFE
mTLS caller. Only the resulting typed identity context reaches the policy.

The policy expands each rule into exact tuple bindings and rejects duplicate
keys rather than choosing an arbitrary rule. Required scopes use set inclusion.
Unknown tuples deny. Structured decisions contain verified identity metadata,
target/tool, decision, and reason code, but the audit event schema has no token
field. Allowed requests fail closed when auditing is unavailable.

Failure tests cover forged AgentID, wrong workload, wrong purpose, missing
scope, wrong target, unapproved tool, missing verified context, duplicate
bindings, unknown JSON fields, and empty policy. The live lab proves the
allowlisted `system.whoami` path still reaches the API with one correlated
transaction ID.
