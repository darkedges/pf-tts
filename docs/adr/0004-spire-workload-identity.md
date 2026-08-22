# ADR 0004: SPIRE provides workload identity

Status: Accepted

## Decision

Use SPIRE JWT-SVIDs for actor authentication to PingFederate and rotating
X.509-SVIDs for workload-to-workload mTLS. The Workload API endpoint is
configuration, supporting Unix sockets and Windows named pipes.

## Consequences

Runtime identity derives from attestation rather than request claims. SPIRE is
a critical trust anchor. Join-token node attestation and Docker privileges are
development-lab choices, not production defaults.
