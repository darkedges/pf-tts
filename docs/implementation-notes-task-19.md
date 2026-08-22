# Implementation Notes: Task 19

Acceptance criteria: provide SPIRE Server and Agent lab examples for the demo
agent, MCP gateway, demo MCP server, and protected API. Each workload must use
a different SPIFFE ID derived from a different externally observed Docker
label selector. The lab must not issue one shared identity to every workload.

The existing server and agent configurations use trust domain `example.org`,
the Docker workload attestor, and a shared Workload API socket. The idempotent
registration script creates exactly four entries beneath the single attested
lab node. Tests now reject duplicate SPIFFE IDs as well as duplicate selectors.
