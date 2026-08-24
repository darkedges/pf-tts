# Transaction Tokens Conformance Evidence

## Scope and status

This report is pinned to `draft-ietf-oauth-transaction-tokens-11` (30 July
2026). The agent-specific comparison is separately pinned to
`draft-oauth-transaction-tokens-for-agents-06` (11 April 2026). Both are
Internet-Drafts and may change.

The strict profile is a closest-safe alignment implementation. It is not an
IETF conformance certification, native PingFederate Transaction Tokens
support, or a claim of compatibility with Tokenetes. The normal workbench
remains separate from the opt-in strict profile.

## Implemented base-profile behavior

| Requirement | Status | Evidence |
| --- | --- | --- |
| Trust Domain audience and required signed claims | Implemented in strict mode | `pkg/transaction/txn_verifier.go`; strict verifier tests |
| Exact `txntoken+jwt` JOSE type and RS256 allowlist | Implemented | PingFederate `TokenProfile.java`; Go verifier rejection tests |
| Short-lived TTS-signed immutable token | Implemented with exact 20-second local lifetime | PingFederate issuer tests and Task 46 clean live gate |
| Dedicated HTTP transport | Implemented | `pkg/transaction/transport.go` accepts exactly one `Txn-Token` and rejects legacy Authorization coexistence |
| Independent validation at every receiving workload | Implemented | strict middleware and gateway/MCP/API handler tests |
| Immediate caller authentication independent of the token | Implemented | exact SPIFFE X.509-SVID mTLS policies; Task 46 wrong-workload rejection |
| Original external credentials stop at the TTS | Implemented | agent/adapter boundary tests and bounded leak scans |
| Same transaction context throughout the Call Chain | Implemented | immutable propagation tests and Task 46 correlation gate |

## Local WAI agent profile

The local profile keeps user, logical agent, agent instance, requesting
workload, and transaction identities distinct. PingFederate derives the
logical AgentID from the verified actor JWT-SVID through trusted workload
binding. It emits `req_wl` and the bounded `tctx.wai` object containing the
approved agent, purpose, target, and tool. Downstream authorization requires
the signed route to match the actual MCP invocation.

The actor JWT-SVID is requester evidence used only at issuance. It is not
forwarded through the Call Chain. The optional `act` model from
`draft-oauth-transaction-tokens-for-agents-06` is not implemented and is not
claimed as a base Transaction Tokens requirement.

## PingFederate outer-wire deviation

PingFederate 13.1 signs and issues the strict inner JWT, remaining the only
signing and issuance-policy authority. Its tested access-token-manager path
does not natively accept the Transaction Token requested type or return
`issued_token_type=urn:ietf:params:oauth:token-type:txn_token` with
`token_type=N_A`.

The separately addressed, non-signing TTS adapter supplies those outer response
semantics. It authenticates the requester with exact SPIFFE mTLS, forwards the
subject and actor evidence only to the fixed PingFederate endpoint, verifies
the returned PingFederate signature and signed requester binding, and returns
the unchanged compact token. It cannot sign, rewrite, or broaden the token.
This is an explicit product deviation, not native PingFederate support.

## Security hardening beyond the draft baseline

- Issuers and algorithms are locally allowlisted; token headers cannot select
  a trust algorithm.
- Every network hop requires an exact immediate-caller SPIFFE ID rather than
  trust-domain-wide TLS authorization.
- Token, context, identifiers, scopes, bodies, responses, and log capture have
  explicit size bounds.
- Missing, duplicate, comma-joined, conflicting, ambiguous, or legacy token
  candidates fail closed.
- Raw subject, actor, transaction, client, cookie, and private-key material is
  prohibited from logs and errors.

## Known limits and exclusions

The strict profile does not provide early invalidation of an already issued
20-second token, a distributed replay cache, proof of possession for the
Txn-Token itself, cross-domain federation, replacement tokens, or the optional
agent `act` extension. These are not silently treated as implemented. Normal
workbench cutover requires a separate operational decision and rollback plan.

## Repeatable evidence

- `go test ./...`
- `go vet ./...`
- `make pf-test-strict-call-chain`
- `docs/implementation-notes-task-34.md` through
  `docs/implementation-notes-task-46.md`
