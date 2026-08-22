# PingFederate Integration

## Role

PingFederate is the MVP transaction-token issuer.

Use OAuth 2.0 Token Exchange (RFC 8693).

PingFederate's Token Exchange Processor Policy (TEPP) should validate and combine:

- subject token: user OAuth access token,
- actor token: SPIRE-issued JWT-SVID.

## Request contract

HTTP:

```text
POST <configured PingFederate token endpoint>
Content-Type: application/x-www-form-urlencoded
Authorization: <configured OAuth client authentication>
```

Form:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<user access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
actor_token=<SPIRE JWT-SVID>
actor_token_type=urn:ietf:params:oauth:token-type:jwt
requested_token_type=urn:ietf:params:oauth:token-type:access_token
audience=<configured target audience>
scope=mcp:invoke
```

Do not put `subject_token` or `actor_token` in the URL or query string.

## Recommended actor JWT-SVID audience

Use a dedicated value, for example:

```text
urn:pingfederate:token-exchange
```

Do not use a broad audience shared with arbitrary services.

The SPIRE JWT-SVID audience and the transaction JWT audience are different concepts:

```text
JWT-SVID audience:
  PingFederate token-exchange verifier

Transaction JWT audience:
  mcp-gateway / protected resource
```

## TEPP logical processing

1. Authenticate the OAuth client making the token-exchange request.
2. Validate `subject_token`.
3. Validate `actor_token`.
4. Extract verified actor SPIFFE ID.
5. Resolve the allowed logical AgentID from trusted policy.
6. Reject unknown or conflicting actor SPIFFE IDs.
7. Create or accept only tightly controlled transaction metadata.
8. Map a minimal set of subject claims.
9. Mint a short-lived JWT access token.
10. Restrict audience and scope.

## Important AgentID rule

Do not trust:

```text
agent_id=urn:agent:customer-support
```

merely because the exchange client sends it.

Instead:

```text
verified actor SPIFFE ID
        |
        v
trusted TEPP mapping / attribute lookup
        |
        v
logical AgentID
```

## Suggested transaction-token claims

Use PingFederate's supported access-token attribute/JWT mapping mechanism.

Conceptual output:

```json
{
  "iss": "https://pf.example.invalid",
  "sub": "user-123",
  "aud": ["urn:wai:mcp-gateway"],
  "scope": "mcp:invoke",
  "jti": "019...",
  "agent_id": "urn:agent:customer-support",
  "agent_instance_id": "019...",
  "workload_id": "spiffe://example.org/agent/customer-support",
  "transaction_id": "019...",
  "transaction_purpose": "read-customer-record",
  "iat": 0,
  "exp": 0
}
```

Flat private claims are acceptable for the MVP if PingFederate mapping is simpler and the Go verifier is strongly typed.

Do not prioritize nested JSON claims over operability.

## Transaction ID and purpose

Two acceptable MVP approaches:

### Preferred

The exchange client sends a cryptographically generated transaction ID and a constrained purpose value, and the TEPP accepts them only from an authenticated client under strict validation.

### Stronger later model

Have a trusted server-side policy/adapter derive or mint transaction metadata.

Do not accept arbitrary unbounded purpose text and use it directly for authorization.

Prefer an enum-like value:

```text
customer.read
flight.search
file.read
```

## TTL

Start with a 15–30 second transaction JWT.

Make it configurable, with an explicit maximum.

The output token is not a login session and must not be refreshable in the MVP.

## OAuth client authentication

Prefer a confidential client authentication method appropriate for the PingFederate deployment.

Do not store the client secret in repository configuration.

Allow secret injection through environment/secret-store mechanisms.

Consider stronger client authentication later, but do not block the first vertical slice on it.

## JWKS and verification

The MCP gateway and services must independently verify PingFederate-issued transaction JWTs.

Configure:

- expected issuer,
- JWKS source,
- algorithm allowlist,
- required audiences,
- allowed clock skew.

Never use introspection as a substitute for local validation unless the chosen token format or deployment requires it.

## PingFederate lab checklist

Configure:

1. OAuth client for token exchange.
2. Token Exchange grant enabled.
3. TEPP assigned to the client or as appropriate.
4. subject-token processor for the user access token.
5. actor-token JWT processor capable of validating SPIRE JWT-SVIDs.
6. actor-token trust/JWK material from the SPIFFE trust domain.
7. TEPP attribute contract.
8. actor SPIFFE ID → logical AgentID mapping.
9. access token manager/JWT output mapping.
10. short token lifetime.
11. audience restriction.
12. scope restriction.
13. no refresh-token issuance for the transaction token.

Version-specific PingFederate UI field names should be documented during the lab implementation against the deployed PingFederate release.

## Exact PingFederate 13.1 lab configuration

The reviewed local target is PingFederate `13.1.0.5`. Terraform under
`deploy/pingfederate/terraform` is authoritative; use the Admin UI only to
inspect the resulting objects, not to create competing copies.

### Applied resource identities

| Purpose | PingFederate object | ID / value |
| --- | --- | --- |
| User access tokens | Reference ATM | `waiUserAccessToken` |
| Subject validation | OAuth Bearer Access Token Token Processor | `waiUserAccessToken` |
| Actor validation | WAI SPIRE JWT-SVID Token Processor | `waiSpireJwtSvid` |
| Exchange policy | Token Exchange Processor Policy | `wai-agent-transaction` |
| Transaction JWTs | WAI Exact-TTL JWT ATM | `waiTransactionToken` |
| Exchange client | Confidential OAuth client | `wai-agent-token-exchange` |
| Actor audience | JWT-SVID required audience | `urn:pingfederate:wai:token-exchange` |
| Output audience | Transaction JWT audience | `urn:wai:mcp-gateway` |
| Allowed scope | OAuth scope | `mcp:invoke` |

The OAuth client enables only the `TOKEN_EXCHANGE` grant, requires secret
authentication, references `wai-agent-transaction`, restricts scope to
`mcp:invoke`, and is restricted to `waiTransactionToken`. Supply its secret as
`TF_VAR_token_exchange_client_secret`; never write it to Terraform variables
files.

### Subject-token processor

The processor uses descriptor
`org.sourceid.wstrust.processor.oauth.BearerAccessTokenTokenProcessor` and
validates the opaque user token through the `waiUserAccessToken` reference ATM.
Its `user_id` extension must exactly match the ATM contract. The TEPP mappings
are:

```text
subject  <- SUBJECT_TOKEN.user_id
user_id  <- SUBJECT_TOKEN.user_id
scope    <- SUBJECT_TOKEN.scope
```

This is a validation boundary: `user_id` is accepted only after the reference
ATM has validated the bearer token. Do not map it from an exchange request
parameter.

### Actor-token processor

The processor uses the reviewed custom descriptor
`org.example.wai.spiffe.SpiffeJwtTokenProcessor`. Its configuration is:

```text
Required Audience:          urn:pingfederate:wai:token-exchange
Trust Domain:               example.org
Maximum Lifetime Seconds:   300
Allowed Clock Skew Seconds: 5
SPIRE JWKS:                 exported reviewed signing key set
```

It permits only `ES256`, verifies the JWT-SVID signature before reading its
subject, requires exactly one audience match, and rejects unknown keys,
unexpected trust domains, excessive lifetimes, and ambiguous identity. The
TEPP maps `workload_id <- ACTOR_TOKEN.sub` and has
`actor_token_required = true`; a user token without a valid actor token fails.

### Trusted workload-to-agent mapping

The approved lab bindings are:

```text
spiffe://example.org/agent/demo -> urn:agent:demo
spiffe://example.org/agent/web-app -> urn:agent:web-app
```

This binding must be evaluated inside PingFederate or a trusted server-side
adapter after actor validation. It must use exact matching and fail for unknown
or multiple matches. Never expose `agent_id` as a client-controlled form
parameter or map it directly from `REQUEST`.

The TEPP leaves `agent_id` as `NO_MAPPING`; the custom transaction ATM derives
it by exact lookup of the verified `workload_id` in its bounded configured
`Agent Bindings` allowlist. It overwrites any caller assertion with the mapped
logical AgentID and rejects an unknown workload.

### Transaction metadata

The exact-TTL issuer also requires `agent_instance_id`, `transaction_id`, and
`transaction_purpose`. For the MVP they may come from an
authenticated-client-only adapter that:

- accepts cryptographically generated, bounded instance and transaction IDs;
- accepts only `customer.read` or `system.whoami`;
- rejects missing, repeated, oversized, or unknown values;
- never accepts `agent_id`, `workload_id`, or `user_id` from the request.

These fields remain `NO_MAPPING` in the TEPP. The custom ATM generates distinct
cryptographically random transaction and agent-instance IDs server-side and
uses its configured allowlisted purpose. Callers cannot choose these values.

### Transaction JWT manager

`waiTransactionToken` uses
`org.example.wai.transaction.ExactTtlJwtAccessTokenManager` with a
PingFederate-managed RSA signing key. It issues `RS256` JWTs with issuer
`https://localhost:9031`, audience `urn:wai:mcp-gateway`, and an exact 20-second TTL
(hard maximum: 60 seconds).

Its fixed allowlisted contract is `sub`, `agent_id`, `agent_instance_id`,
`workload_id`, `transaction_id`, `transaction_purpose`, `scope`, and `aud`.
The `wai_provider_contract_marker` extension exists only because the Terraform
provider requires one extension; it is `NO_MAPPING` and the issuer never emits
it.

### Required negative checks

Before calling the lab complete, demonstrate rejection of:

- missing or invalid subject token;
- missing, wrongly signed, expired, or wrong-audience actor token;
- actor `sub` outside `example.org` or not exactly bound to an AgentID;
- caller-supplied logical AgentID;
- missing or unapproved purpose;
- missing transaction or agent-instance ID;
- a scope other than `mcp:invoke`;
- an ATM other than `waiTransactionToken`.

Never weaken required-claim checks to make a partially mapped policy issue
tokens.
