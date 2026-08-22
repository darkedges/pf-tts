# ADR 0001: Immutable transaction token

Status: Accepted

## Decision

PingFederate signs the transaction context once. Every hop forwards the exact
same JWT and no intermediary adds, removes, or rewrites claims.

## Consequences

Tampering is detectable and one transaction ID correlates the chain. Caller
identity is not encoded as mutable hop history; it is authenticated separately
with mTLS. Per-hop downscoping is deferred.
