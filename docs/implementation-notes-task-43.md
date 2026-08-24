# Implementation Notes: Task 43

## Outcome

Task 43 adds separate strict MCP server and protected API constructors. The MCP
tool handlers require their invoked target/tool to equal the signed route. The
`system.whoami` API call propagates the immutable verified token with exactly
one `Txn-Token` field and no Authorization credential.

The strict API handler independently requires its configured signed route,
typed verified identity, immutable verified token context, and absence of an
Authorization field. Its response contains only transaction correlation data
and is marked `no-store`.

## Trust boundaries and failures

The MCP protocol method is request-controlled even after gateway routing, so
the server repeats signed target/tool agreement. The API repeats the check
again and relies on the separate strict middleware for signature and
immediate-caller authentication. Neither handler parses claims or trusts an
inbound identity header.

Tests cover missing context, legacy Bearer coexistence, unsafe downstream
configuration, downstream denial, unknown response fields, correlation
mismatch, exact unchanged strict propagation, and token/credential leakage.
The strict response decoder is bounded and rejects trailing or unknown data.

## Remaining work

Legacy handlers and commands are unchanged. The next task must assemble these
strict constructors with Task 40 middleware and exact SPIFFE peers in a
separately addressed stack; only that complete stack may proceed to a live
atomic migration gate.
