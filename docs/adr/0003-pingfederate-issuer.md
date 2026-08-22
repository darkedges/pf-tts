# ADR 0003: PingFederate is the transaction issuer

Status: Accepted

## Decision

Use PingFederate RFC 8693 processing and a dedicated exact-TTL JWT access-token
manager. Consumers allowlist issuer, audience, algorithm, and signing keys.

## Consequences

Subject/actor validation and issuance policy remain centralized. PingFederate
and its signing key are high-value trust anchors. Applications do not mint
transaction tokens or weaken required claims when mappings are incomplete.
