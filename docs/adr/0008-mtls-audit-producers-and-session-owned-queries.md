# ADR 0008: mTLS audit producers and session-owned queries

Status: Accepted

## Decision

The local audit collector treats an exact allowlist of SPIFFE-authenticated
service workloads as trusted producers of fixed-schema audit summaries. It
derives and stores the submitting SPIFFE ID from the verified mTLS certificate
and rejects any caller outside that allowlist. Producers derive transaction
and user metadata from verified transaction middleware; the collector accepts
no raw headers, bodies, arguments, tokens, or extensible metadata maps.

Only the exact web-app SPIFFE workload may query the collector. The BFF derives
the query user from its authenticated server-side session. The collector
filters every list and detail lookup by that user and returns not found for
both absent and cross-user identifiers.

## Consequences

The in-memory MVP provides bounded retention, exact workload attribution,
credential-safe records, and user isolation without creating another token
audience or mutating the immutable transaction token. A compromised
allowlisted producer could submit false typed metadata. Production deployments
that cannot trust producers at this boundary require signed event attestation
or a collector-side transaction-verification design with its own explicitly
audienced proof; they must not reuse a gateway-audience bearer token.
