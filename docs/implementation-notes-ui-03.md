# UI-03 implementation notes

Acceptance criteria: implement Authorization Code with S256 PKCE start and
callback handlers, bounded server-side pre-authentication and authenticated
session state, a safe session view, CSRF-protected logout, and strict ID-token
verification of signature, pinned algorithm, key ID, issuer, audience, nonce,
and time claims. Cover forged and replayed state, nonce, issuer, audience,
signature, expiry, session fixation, CSRF, and credential leakage failures.

The browser is an untrusted boundary. It receives only a fresh 256-bit opaque
session identifier in a `Secure`, `HttpOnly`, `SameSite=Lax`, `__Host-` cookie.
OAuth codes, PKCE verifiers, subject access tokens, ID tokens, and the client
secret remain server-side. State is atomically consumed before token exchange,
so a failed or successful callback cannot be replayed.

PingFederate is trusted only through a configured HTTPS issuer, JWKS endpoint,
explicit signature-algorithm allowlist, and exact browser client audience. The
verified ID-token subject is the only login identity accepted. Multiple token
audiences require an exact `azp` binding to the configured client. Unknown or
ambiguous key IDs and missing required claims fail closed.

Pre-authentication records and sessions are TTL-limited maps with configured
capacity. Capacity exhaustion fails the request rather than evicting an active
identity. Authentication endpoints are marked `no-store` and use a
`no-referrer` policy. Logout requires both a valid opaque session and
constant-time CSRF-token comparison from the exact configured origin.
