# UI-04 implementation notes

Acceptance criteria: reuse the existing SPIFFE JWT-SVID, RFC 8693 exchange,
transaction-token verification, and SPIFFE mTLS gateway invocation path from
the browser BFF; bind the web workload to `urn:agent:web-app` in PingFederate
and OPA; permit only server-configured tool/purpose pairs; and reject browser
identity or routing overrides, absent subject sessions, wrong workload
bindings, exchange failures, and downstream rejection.

The browser remains untrusted. `POST /api/interactions` accepts exactly `tool`
and `purpose` in a bounded JSON body and requires the authenticated opaque
session, exact-origin check, and CSRF token. Unknown fields are rejected, so a
browser cannot submit AgentID, workload identity, target URL, user token, or
transaction metadata. Only an exact server-side `AllowedInteraction` tuple can
reach credential use.

The BFF passes its server-held subject token to the reusable agent runner. The
runner obtains the actor JWT-SVID, exchanges the two credentials, verifies the
issued transaction JWT, and compares the verified AgentID, workload SPIFFE ID,
purpose, and audience to trusted configuration before sending only the
transaction token to the fixed gateway over SPIFFE mTLS. It returns only the
verified transaction ID to the browser.

PingFederate remains the workload-to-logical-agent trust boundary. The custom
ATM now accepts a bounded, exact `SPIFFEID=AgentID` allowlist and resolves the
verified actor workload through that map. Unknown workloads fail before token
issuance and caller AgentID assertions are overwritten. The lab allowlist adds
`spiffe://example.org/agent/web-app=urn:agent:web-app`; OPA independently
requires that same exact pair for `demo/system.whoami` with purpose
`system.whoami` and scope `mcp:invoke`.
