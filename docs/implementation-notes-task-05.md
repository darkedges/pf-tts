# Implementation Notes: Task 05

Acceptance criteria: use go-spiffe behind the core provider boundary; accept a
configured Workload API endpoint; fetch JWT-SVIDs for explicit audiences;
maintain a rotating X.509 source; select one exact expected SPIFFE ID; fail on
zero, multiple, nil, or unexpected SVIDs; document Linux Unix-socket and Windows
named-pipe endpoint forms; and close owned resources.

Trust boundary: the expected SPIFFE ID comes from trusted deployment
configuration. The Workload API cryptographically issues identities, but a
workload may receive more than one registered identity. The adapter therefore
does not treat ordering as authorization and rejects ambiguity. Failure tests
cover zero, multiple, nil, and mismatched candidates for both JWT and X.509
SVIDs.

JWT audiences are caller requirements passed to the trusted Workload API, not
identity claims accepted from an inbound request. Empty and duplicate audiences
are rejected. Raw JWT-SVIDs remain confined to the transport result and are not
included in errors or logs.

The adapter requires an explicit peer policy when constructing its mTLS client
configuration. It does not provide an authorize-any fallback.

The provider owns one Workload API client and rotating X.509 source. Closing
either the provider or its returned core X.509 handle closes both owned
resources exactly once. Tests cover this lifecycle contract and the rejection
of missing peer policy. A build-tagged integration test can exercise a live
SPIRE Agent without making it a normal test dependency.
