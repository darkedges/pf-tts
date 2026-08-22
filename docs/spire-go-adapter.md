# SPIRE go-spiffe Adapter

Task 05 implements the SPIRE Workload API boundary in `pkg/spiffe/spire` using
`github.com/spiffe/go-spiffe/v2`.

Construction requires both a Workload API endpoint and one exact expected
SPIFFE ID. The expected ID is trusted deployment configuration, not request
input. The adapter rejects zero, multiple, nil, or unexpected JWT- and
X.509-SVID candidates instead of selecting the first candidate.

Endpoint examples:

```text
Linux:  unix:///run/spire/sockets/agent.sock
Windows: npipe:spire-agent/public/api
```

The literal endpoint remains in configuration and is passed to go-spiffe; core
identity code does not assume Unix sockets. The X.509 source watches the
Workload API and supplies rotated material without a process restart.

The returned TLS configuration is an mTLS client configuration and requires an
explicit peer policy. Task 12 will add separately named client/server HTTP
helpers; this adapter does not default to authorizing arbitrary SPIFFE IDs.

Call `Provider.Close` during shutdown. Closing the returned X.509 handle has the
same effect, and repeated closes are safe. Both paths close the rotating X.509
source and underlying Workload API client exactly once. Errors and tests never
include raw JWT-SVID values.

An opt-in live test is available with build tag `spire_integration`. Set
`SPIFFE_ENDPOINT`, `SPIFFE_EXPECTED_ID`, and `SPIFFE_TEST_AUDIENCE`; the normal
unit suite remains independent of a running SPIRE Agent.
