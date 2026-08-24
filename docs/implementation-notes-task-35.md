# Implementation Notes: Task 35

## Acceptance criteria implemented

Task 35 adds an offline, product-neutral model and verifier for the inner
draft-11 Transaction Token JWT. It introduces explicit
`legacy-wai-jwt` and `ietf-txn-token-v11` modes, typed claims, a bounded local
`tctx.wai` profile, optional bounded `rctx`, strict JOSE requirements, trusted
workload-to-agent binding, narrow scope validation, and an injected
verification-key boundary.

The new verifier is not connected to application configuration, middleware,
PingFederate issuance, HTTP transport, OPA, PingAuthorize, Terraform, or the
normal workbench. Existing routes therefore remain in their current legacy
mode and cannot ambiguously accept both profiles.

## Trust boundaries

The compact token is untrusted until its single JWS signature has been
verified with a key returned by the configured key resolver. Structural limits
and duplicate-key checks may reject malformed input before signature
verification, but no decoded claim is returned or used for authorization
before verification.

The key resolver represents the issuer trust boundary. It receives only the
bounded protected `kid`; it must return exactly one trusted verification key
or fail. The verifier separately constrains the protected algorithm and does
not select trust from the token header. Allowlisted scopes, algorithms, and
workload bindings are copied at construction so later mutation of a caller's
configuration objects cannot change verifier trust.

The `req_wl` value is signed issuer output, but it is not sufficient by itself
to establish a logical agent. The verifier requires exact agreement between:

- signed `req_wl`;
- signed `tctx.wai.agent.workload_id`;
- signed `tctx.wai.agent.id`; and
- the local trusted SPIFFE workload-to-agent binding.

This prevents a signed but incorrectly mapped local profile, or a future
caller assertion accidentally copied by an issuer, from changing the logical
agent identity.

The Trust Domain audience intentionally identifies a broader cryptographic
recipient set than the current gateway audience. Task 35 therefore validates
only tokens with allowlisted narrow scopes and requires bounded signed target
and tool context. Actual route/tool comparison remains the responsibility of
the later atomic policy cutover; the new verifier is unreachable until that
comparison exists.

## Validation rules

- Compact JWS only, with exactly three segments and one signature.
- Protected `typ` exactly `txntoken+jwt`.
- Protected, bounded, non-empty `kid` and configured algorithm.
- No unprotected JOSE fields or unsupported protected fields.
- Duplicate keys rejected recursively in protected headers and claims.
- Unknown top-level claims ignored for draft extensibility.
- Unknown fields inside repository-owned `tctx.wai` and `rctx` rejected.
- Exact configured HTTPS issuer and exact lowercase Trust Domain audience.
- Required bounded subject, transaction ID, requester workload, agent ID,
  instance ID, target, tool, scope, `iat`, and `exp`.
- Expiry, future issuance, maximum lifetime, and configurable skew enforced.
- Scope whitespace canonicalized, duplicates rejected, and every scope
  allowlisted.
- Requesting SPIFFE ID must be in the audience Trust Domain and match the local
  trusted workload-to-agent binding.
- Compact token, decoded payload, protected header, identifiers, scope count,
  and local context have explicit limits.

## Failure coverage

Tests reject invalid/automatic profile modes, wrong or unprotected JOSE type,
duplicate protected fields, disallowed algorithms, missing or unknown key IDs,
bad signatures, wrong issuer or audience, expired/future/overlong tokens,
scope expansion and duplication, requesting-workload conflicts, forged agent
bindings, unknown local context fields, oversized context, duplicate claim
keys, and oversized compact tokens.

No validation was weakened to accommodate PingFederate 13.1. Task 34's outer
wire-profile non-conformance remains explicit and independent of this inner
JWT verifier.

## Rollback and next dependency

Rollback is deletion of the new offline types, verifier, and tests; no running
configuration has changed. Phase C must not activate the profile until
PingFederate emits the exact inner JWT and clean-bootstrap tests cover every
negative case. The Trust Domain audience must not reach normal routes until
target, tool, scope, and immediate-caller policy move atomically with the
transport cutover.
