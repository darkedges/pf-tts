# ADR 0002: Separate immediate-caller mTLS identity

Status: Accepted

## Decision

Every protected hop requires SPIFFE X.509-SVID mTLS and authorizes the exact
peer independently of the transaction JWT.

## Consequences

A stolen transaction token is insufficient from the wrong workload, and the
API can reject direct agent calls. Services must maintain explicit peer policy
and rotating Workload API sources; `AuthorizeAny` is not a production default.
