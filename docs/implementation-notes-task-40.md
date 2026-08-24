# Implementation Notes: Task 40

## Outcome

Task 40 adds a constructor-built strict middleware path. It accepts only the
Task 39 `Txn-Token` field, runs the Task 35 verifier, independently extracts an
allowlisted immediate SPIFFE caller, and only then creates typed identity,
non-replayable audit evidence, immutable-token context, and a separately typed
signed target/tool context.

## Trust boundaries

The HTTP field and compact token are untrusted until strict verification
passes. The verifier remains authoritative for issuer, signature, Trust
Domain, time, scope, requesting workload, logical agent binding, and signed
transaction context. The TLS peer certificate independently establishes the
immediate caller; it is not required to equal the original requesting workload
on downstream hops, but it must be in the service's exact copied allowlist.

The signed target and tool remain distinct policy inputs. For compatibility
with the existing required transaction-purpose field, middleware derives the
display/audit purpose as `target:tool`; this does not make that string a new
identity or caller assertion.

## Failure behavior

Bearer coexistence, failed verification, missing or ambiguous TLS identity,
wrong callers, malformed typed identity, and audit sink failure all fail
closed. Trusted raw-token, identity, evidence, and signed-route context are
installed only after every check and required audit write succeeds.

The caller allowlist is copied at construction. Tests prove later mutation of
the caller-owned map cannot remove the approved identity or add another one.

## Remaining work

No command or runtime route uses this middleware yet. The next Phase E task
must require signed target/tool agreement in authorization and strict
downstream propagation before a separately addressed full-stack cutover.
