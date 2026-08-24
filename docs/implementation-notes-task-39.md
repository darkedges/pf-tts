# Implementation Notes: Task 39

## Acceptance criteria implemented

Task 39 adds the product-neutral strict `Txn-Token` HTTP field boundary. It
requires exactly one bounded compact JWS value, prohibits `Authorization`
coexistence, and rejects missing, duplicate, comma-folded, whitespace,
control-character, malformed, and oversized values. Propagation writes one
field only to a clean destination and never replaces existing credentials.

## Trust boundary

HTTP fields are attacker-controlled transport data. Extraction establishes
only that the request has one unambiguous strict transport value; it does not
establish token authenticity. Callers must run the Task 35 signature, issuer,
Trust Domain, time, scope, workload, and context verifier before using claims.

The generic transport error never contains field contents. This prevents a
raw Txn-Token or legacy bearer credential from crossing into logs or error
responses. Existing destination credentials cause propagation to fail closed
without mutation.

## Failure tests

Table-driven tests cover legacy Bearer coexistence, even an empty
Authorization field, duplicate values, proxy-style comma folding, whitespace,
control characters, invalid compact structure/alphabet, oversized input,
non-positive bounds, existing downstream credentials, and mutation on
failure.

## Rollback and remaining work

Task 39 is not wired into any command, middleware, policy adapter, Compose
profile, or normal workbench route. Rollback is therefore removal of this
unused boundary. The next Phase E task must add strict verification middleware
and typed signed target/tool context without enabling a dual Bearer fallback.
