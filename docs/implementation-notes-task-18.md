# Implementation Notes: Task 18

Acceptance criteria: document the exact PingFederate 13.1 lab resources for
the OAuth client, token exchange grant, subject and actor processors, TEPP,
attribute contracts, trusted SPIFFE-to-AgentID resolution, transaction JWT
manager, output mapping, short TTL, and audience restrictions. Version-specific
names must be explicit and secrets must remain external.

The custom transaction ATM now owns the trusted metadata boundary. It binds one
exact verified workload to one logical agent, generates IDs server-side, and
uses an allowlisted configured purpose while the TEPP leaves caller-controlled
fields unmapped.
