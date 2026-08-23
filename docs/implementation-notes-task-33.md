# Implementation Notes: Task 33

## Acceptance criteria

Task 33 reviews the repository against the CNCF Tokenetes model and the
version-pinned IETF Transaction Tokens base and agent drafts. It produces an
evidence-based requirement matrix, claim mapping, Ping product capability
review, compatibility strategy, conformance test plan, and phased backlog. It
does not modify token issuance, validation, transport, product configuration,
or service behavior.

The complete review is in
[`transaction-tokens-alignment-plan.md`](transaction-tokens-alignment-plan.md).

## Trust boundaries

PingFederate remains the only transaction JWT signer and logical Transaction
Token Service. The user subject token and SPIRE actor token are independently
validated at that boundary. A Txn-Token conveys immutable authorization
context; it is neither workload authentication nor an OAuth access token.
SPIFFE mTLS continues to authenticate the immediate caller, and PingAuthorize
or OPA evaluates only typed values created after token and caller validation.

The proposed audience and HTTP header migration changes effective
authorization. It must therefore be atomic and fail closed. A protected route
must never auto-detect or silently prefer between legacy bearer and Txn-Token
formats. The target, tool, narrow scope, original workload, logical agent, and
immediate caller must remain independently bound when the token audience moves
from one logical resource to the Trust Domain.

## Principal findings

The existing implementation closely matches the Transaction Tokens
architecture: one issuer, RFC 8693 exchange, short-lived signed context,
immutable propagation, independent workload authentication, exact policy, and
safe correlation. It does not match the wire profile: the JWT is an OAuth
access token with `typ=at+jwt`, application-specific claims, resource audience,
Bearer response semantics, and `Authorization` propagation.

The custom PingFederate plugin can control the inner JWT header, claims, and
lifetime. Official PingFederate documentation does not list the Transaction
Token URN as a supported token-exchange output type, so the outer request and
response remain a product capability blocker. The first future implementation
phase is an isolated PingFederate 13.1 capability gate. No adapter is approved
by this task.

## Failure planning

The migration plan requires negative tests for incorrect token type, JOSE
header, issuer, trust-domain audience, time, transaction ID, subject, scope,
requesting workload, context schema, key ID, algorithm, HTTP header count,
legacy bearer presentation, SPIFFE caller, target authority, immutable
propagation, and credential leakage. Validation must become stricter during
migration; unsupported product behavior is documented or stops the migration
rather than being accepted ambiguously.

## Runtime changes

None. Task 33 changes documentation only.
