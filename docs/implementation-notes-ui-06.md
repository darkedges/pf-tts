# UI-06 implementation notes

Acceptance criteria: provide a responsive interaction workspace using the left
two-thirds of the viewport and a selectable audit trail using the right third;
show authentication, approved invocation, result, transaction grouping, hop,
decision, and safe detail states; support keyboard and narrow-screen use; and
keep all credentials and cryptographic material out of browser-visible state.

The interface is embedded HTML, CSS, and JavaScript served by the Go BFF. It
uses no runtime package manager, remote font, analytics, third-party script, or
inline script/style. A restrictive CSP permits only same-origin scripts,
styles, images, fonts, and API connections. Authentication and API responses
remain `no-store`, framed embedding is denied, and browser capabilities such as
camera, microphone, location, and payment are disabled.

The browser holds the CSRF value only in JavaScript memory and the opaque
session identifier only in its HttpOnly cookie. It does not use local or
session storage and never reads or sends an OAuth token, actor JWT-SVID,
transaction token, client secret, or SPIFFE key. All service and audit values
are rendered with `textContent`; raw HTML rendering APIs are absent.

The runnable `web-app` BFF pins its logical identity and SPIFFE workload in
code, uses SPIFFE mTLS for gateway and audit-collector connections, and requires
conventional HTTPS certificate/key files for the browser-facing listener. A
browser is not incorrectly required to possess a SPIFFE workload certificate.
The exact callback route is `/oauth/callback`; endpoint queries, alternate
callback paths, non-root public origins, and insecure service URLs fail
configuration.

The UI groups audit events by verified transaction ID, orders them by
collector sequence, and exposes only the fixed safe detail allowlist. It has
signed-out, ready, loading, empty, completed, denied, unavailable, and detail
states; native form controls, labels, landmarks, live regions, focus styles, a
skip link, reduced-motion behavior, and narrow-screen stacking are included.
