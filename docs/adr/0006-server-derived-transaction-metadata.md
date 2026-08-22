# ADR 0006: Server-derived transaction metadata

Status: Accepted

## Decision

The PingFederate transaction ATM compares the verified actor `workload_id` to
one exact configured SPIFFE ID, derives the corresponding logical AgentID,
generates transaction and agent-instance IDs with server-side cryptographic
randomness, and supplies one configured allowlisted purpose.

The TEPP does not map these fields from request parameters. Any values asserted
by a caller are overwritten before signing.

## Consequences

The first lab flow is limited to one workload/agent/purpose binding per ATM
instance. Supporting multiple agents or purposes requires separate instances
or a reviewed trusted policy adapter, never relaxed request mappings. A wrong
workload, malformed binding, unknown purpose, or missing verified subject fails
before JWT issuance.
