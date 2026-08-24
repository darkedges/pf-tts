# Implementation Notes: Task 38

## Outcome

Task 38 deploys the Task 37 adapter only as a separately addressed, default-off
SPIFFE workload. The live gate completed against a fresh PingFederate 13.1
container named `wai-pf-clean-c39c5d6f075f172d`; the harness removed that
container and its exact randomly named adapter, images, volume, certificate,
Terraform working directory, and state after success.

The approved `spiffe://example.org/agent/demo` requester received the original
PingFederate-signed strict inner token through the exact Transaction Token
outer response. The probe independently verified its signature, protected
type, Trust Domain, scope, requesting workload, and bounded transaction
context. A probe using `spiffe://example.org/gateway/mcp` was rejected during
SPIFFE mTLS authentication before token processing.

## Trust boundaries and failure behavior

The adapter has its own `spiffe://example.org/tts/adapter` identity selected
from rotating Workload API material. TLS setup allowlists only the demo-agent
requester. The handler derives immediate caller identity exclusively from the
verified peer certificate; forwarded identity fields are not accepted.

PingFederate remains the only signer and the authority for subject, actor,
logical-agent binding, scope, context, and signed lifetime. The adapter uses a
fixed HTTPS token endpoint and a bounded HTTPS JWKS resolver that rejects
redirects, non-success responses, oversized or duplicate-key JSON, and missing
or ambiguous key IDs.

PingFederate can report a relative `expires_in` one second shorter than the
signed `exp - iat` lifetime because time elapses while the response is
serialized. The adapter therefore returns the verified signed lifetime. It
still rejects a non-positive or excessive signed lifetime and rejects any
upstream hint that exceeds the signed lifetime. Tests preserve that failure
case; validation was not weakened to trust the response hint.

Operational failure reports contain only fixed stage names. The live harness
captured approved-probe output, rejected-probe output, and adapter logs and
rejected JWT-shaped strings or known credentials. No raw token was emitted.

## Live evidence

- PASS: strict inner Transaction Token signature and exact 20-second profile.
- PASS: approved SPIFFE requester and exact outer `txn_token`/`N_A` semantics.
- PASS: wrong SPIFFE workload rejected.
- PASS: no token-shaped or known credential output.
- PASS: exact random resources cleaned; normal workbench state was untouched.

## Remaining boundary

The adapter is not part of normal `app-only` or `local-lab` startup. Phase E
must migrate every sender, receiver, policy input, and transport to the strict
`Txn-Token` Call Chain atomically. Dual legacy/strict parsing remains
prohibited, and no end-to-end draft-11 conformance claim is made yet.
