# ADR 0010: Narrow non-signing TTS protocol adapter

## Status

Accepted; the isolated deployment gate passes. Not approved for normal runtime
deployment or a conformance claim until the Call Chain is migrated atomically.

## Context

Task 34 proved that the pinned PingFederate 13.1 OAuth token-exchange endpoint
rejects the Transaction Token requested type and that its bearer Access Token
Manager returns OAuth access-token/Bearer response semantics. Task 36 proved
that the same PingFederate-managed signer can emit the exact strict inner
Transaction Token JWT.

Adding another signer or rewriting the PingFederate-signed JWT would split the
logical TTS trust boundary and obscure which component authorized the
transaction. Treating the existing Bearer response as conformant would weaken
protocol validation.

## Decision

Use a separately addressed, default-off protocol adapter that is part of the
logical TTS deployment but is not a signer.

The adapter:

- authenticates the requester with verified SPIFFE mTLS;
- accepts only one exact bounded draft-11 exchange form;
- translates only the unsupported outer requested token type when calling one
  fixed PingFederate exchanger;
- sends the unchanged subject and actor tokens only in the upstream POST body;
- requires PingFederate's known access-token/Bearer outer response;
- independently verifies the PingFederate signature and strict inner profile;
- requires signed `req_wl` to equal the authenticated mTLS requester;
- returns the original compact token byte-for-byte with the Transaction Token
  issued type and `token_type=N_A`; and
- emits only bounded allowlisted OAuth error codes.

It cannot sign, rewrite, decode-and-resign, route to arbitrary upstreams,
follow redirects, issue refresh tokens, accept legacy shapes, or log token
material.

## Trust boundaries

The inbound TLS verifier is authoritative for the immediate requesting
workload. The actor JWT-SVID remains separately validated by PingFederate. The
strict signed `req_wl` must agree with the TLS identity, preventing a caller
from exchanging another workload's actor token.

PingFederate remains authoritative for subject validation, actor validation,
workload-to-AgentID mapping, scope/context determination, signing and expiry.
The adapter trusts none of those values until the strict verifier validates
the returned compact token.

The upstream exchanger is a fixed HTTPS boundary with explicit timeout,
credential redaction, response limits, no redirects, duplicate-key rejection,
and exact success fields. It is not a general proxy.

## Consequences

Exact outer response interoperability becomes possible without changing the
signed authorization object. The adapter adds an availability-sensitive
component and a new mTLS termination point inside the logical TTS. It must be
deployed and exercised in an isolated SPIFFE stack before use.

Normal application routes remain legacy. End-to-end draft-11 conformance is
not claimed until the adapter, strict issuer, strict verifier, `Txn-Token`
transport and downstream authorization cut over atomically.

## Rejected alternatives

- Calling the Bearer response conformant: hides a tested protocol mismatch.
- A second signing service: creates ambiguous authorization authority.
- Decode and re-sign: permits claim mutation and provenance loss.
- A general reverse proxy: broadens SSRF and credential-disclosure risk.
- Dual legacy/strict auto-detection: creates ambiguous protected routes.
