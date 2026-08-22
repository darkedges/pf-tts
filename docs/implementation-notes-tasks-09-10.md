# Implementation Notes: Tasks 09–10

Typed claims require issuer, subject, audience, expiry, issued-at, JTI, logical
agent, workload, transaction ID, and purpose. Missing fields and invalid times
fail closed.

The PingFederate verifier accepts only configured algorithms, HTTPS issuer/JWKS
locations, an explicit audience, and one unique key selected by `kid`. Claims
are mapped to the typed model only after signature and standard-claim
validation. JWKS and token errors expose reason classes but never raw tokens or
key material.
