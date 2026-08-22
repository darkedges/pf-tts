# Implementation Notes: Task 08

Acceptance criteria: send RFC 8693 exchange parameters only in an HTTPS POST
form body, use explicit token types and audience, support optional scope, inject
an HTTP client with a non-zero timeout, parse success and OAuth failures, and
never retry 4xx responses or expose credentials in errors.

Trust boundary: subject and actor tokens are credentials transported to the
configured PingFederate endpoint. The constructor rejects non-HTTPS endpoints
and query strings, preventing token placement in URLs. OAuth error descriptions
are untrusted and are never reflected; only status and a bounded error code are
returned. Tests inject credential values into failure responses and assert they
do not appear in errors.
