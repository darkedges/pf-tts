# Implementation Notes: Task 37

## Outcome

Task 37 implements the narrow non-signing outer-protocol boundary as an
unwired Go HTTP handler in `pkg/ttsadapter`. It is deliberately not a command,
container, Compose service, Terraform resource, or normal runtime route.

The positive path accepts the exact Transaction Token exchange request,
authenticates the SPIFFE mTLS requester through an injected verified identity
boundary, calls the fixed PingFederate exchanger with its supported access
token requested type, independently validates the returned strict inner JWT,
compares `req_wl` to the mTLS caller, and returns the exact original compact
token with:

```json
{
  "access_token": "<unchanged PingFederate-signed JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:txn_token",
  "token_type": "N_A",
  "expires_in": 20
}
```

No refresh token or response scope is permitted.

## Security decisions and failure behavior

The inbound request is untrusted. The handler rejects non-POST methods,
queries, cookies, Authorization credentials, media-type parameters, oversized
bodies, unknown or duplicate form fields, empty values, wrong token types,
wrong audience, wrong scope, and oversized tokens before upstream exchange.

Subject and actor tokens cross only from the bounded handler into the fixed
injected PingFederate exchange request. They are never returned, logged, put
in a URL, or included in errors.

The PingFederate response is untrusted until the Task 35 verifier validates
the signature and strict claims. The adapter additionally checks caller/
`req_wl`, Trust Domain, scope, and signed expiry. A relative upstream expiry
hint may be shorter due to elapsed processing time but may never exceed the
verified signed lifetime. Any mismatch becomes a generic `server_error`;
verifier details and token material do not cross the outbound response
boundary.

The PingFederate client now clones the injected HTTP client and forces
redirect rejection. It caps responses, rejects duplicate JSON keys, rejects
unknown success fields including `refresh_token`, and continues to redact
credentials and upstream bodies from errors.

Every response sets `Cache-Control: no-store` and `Pragma: no-cache`.

## Tests

Failure tests cover method, query, cookie, Authorization, media type,
duplicates, missing actor, unknown caller fields, wrong requested type,
audience and scope, oversized input, missing authenticated caller, upstream
failure, unexpected outer types, response scope, excessive or inconsistent
expiry, invalid strict JWT, wrong requester workload, wrong verified scope,
redirects, duplicate response keys, refresh-token output and credential
leakage.

The positive test asserts that the verifier receives and the client receives
the same compact string returned by PingFederate, proving that the adapter
does not mutate or replace the signed token.

## Remaining work

Task 38 has now passed the isolated SPIFFE mTLS deployment gate. The adapter
remains outside normal runtime wiring. Phase E must migrate the whole Call
Chain atomically before any conformance claim.
