# ADR 0005: Logical AgentID remains separate from SPIFFEID

Status: Accepted

## Decision

`AgentID` describes an approved logical application; `SPIFFEID` proves the
attested runtime. Trusted configuration maps the latter to the former after
cryptographic validation.

## Consequences

Callers cannot become another agent by sending an `agent_id`. Bindings must be
exact and unambiguous, and unknown workloads fail. The identities remain
separate fields in domain models, tokens, policy, and audit.
