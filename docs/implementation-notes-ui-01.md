# Implementation Notes: UI-01

Acceptance criteria: add typed web, OIDC, session, and audit-store
configuration; require exact secure origins and callback binding; bound all
session and audit state; and register distinct web-app and audit-collector
SPIFFE workload identities.

The browser remains outside the trusted identity boundary. Configuration binds
the web BFF's logical AgentID to its SPIFFE ID through the same trusted agent
registry used elsewhere. The audit collector has a different SPIFFE ID and
cannot be collapsed into the acting workload. SPIRE registration uses distinct
externally observed Docker labels.

OIDC authorization and token endpoints must use HTTPS on the configured issuer
origin. The redirect URI must use the exact web origin and a non-root path.
Plain HTTP is rejected except when an explicit development switch is set and
both public and callback hosts are loopback. The required `openid` scope and
client-secret environment variable name are validated without reading or
storing the secret.

Session configuration requires a `__Host-` Secure SameSite=Lax cookie, an
eight-hour maximum authenticated lifetime, ten-minute maximum pre-authentication
lifetime, and bounded capacity. Audit storage is HTTPS-only and bounded to
100,000 events, 64 KiB per field, and 24-hour retention.

Failure tests cover missing trusted binding, shared workload identity,
non-loopback HTTP, callback and issuer mismatch, off-origin token endpoint,
missing OIDC scope, unsafe cookie settings, invalid secret indirection, and
unbounded session or audit values. No validation was weakened for local use;
the only HTTP exception is explicit and restricted to a loopback address.
