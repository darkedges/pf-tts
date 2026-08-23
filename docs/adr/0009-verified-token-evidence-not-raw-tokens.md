# ADR 0009: Display verified token evidence, never raw tokens

## Status

Accepted.

## Context

The browser audit view must demonstrate that one immutable transaction JWT is
used across the delegated call chain and show its reviewed claims. Returning a
compact JWT to the browser or audit collector would turn an observability
feature into a bearer-credential disclosure path.

## Decision

After signature, issuer, audience, time, and identity-binding validation, each
service derives typed evidence containing:

- the fixed kind `transaction_jwt`,
- a SHA-256 fingerprint of the compact token,
- issuer, audience, scope, JTI, agent-instance ID, issued-at, and expiry.

The fingerprint proves token sameness across hops without being usable as a
bearer credential. Identity and transaction claims already present in the
typed audit record remain visible beside this evidence. Raw tokens, JOSE
segments, arbitrary claims, headers, and request bodies are not representable
in the evidence type.

The collector rejects partial evidence, malformed fingerprints,
credential-shaped values, invalid time bounds, and unknown JSON fields. The UI
renders only an explicit field allowlist and states that the raw token is
withheld.

## Consequences

Operators can compare fingerprints and reviewed claims across hops. They
cannot copy a transaction token from the UI for replay or use unverified JWT
contents for authorization. A change to the displayed claim set requires a
typed schema and security review.
