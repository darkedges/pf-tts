# Implementation Notes: Task 34

## Acceptance criteria

Task 34 runs a sanitized Transaction Tokens capability matrix only after the
existing clean-bootstrap harness has created a random isolated PingFederate
container, volume, ports, certificate, and Terraform state. The harness first
proves the current signed exchange and tampered-actor rejection. It then tests
the Transaction Token requested type, trust-domain audience, request context,
request details, and missing-actor failure without changing the normal
workbench.

The probe validates the exact isolated TLS certificate, rejects redirects and
duplicate JSON keys, caps every HTTP response, uses bounded HTTP/subprocess
timeouts, verifies issued JWT signatures, and outputs only allowlisted
metadata. Subject tokens, actor JWT-SVIDs, issued tokens, credentials, raw
response bodies, error descriptions, and authorization headers are never
printed or persisted.

## Product and specification baseline

- Review profile: `draft-ietf-oauth-transaction-tokens-11`
- PingFederate image:
  `pingidentity/pingfederate:2606-13.1.0@sha256:3a74b4d40398202d7f32b029da4d59c73471bad952dec6225ca22f8857fa6be0`
- Terraform provider: `pingidentity/pingfederate` 1.9.0
- Probe date: 24 August 2026
- Successful isolated run:
  `wai-pf-clean-12c18b51f28a8eb1`
- Cleanup: the exact container, volume, certificate, and isolated Terraform
  directory were automatically removed after success

The random container name is recorded only to prove isolation and cleanup. It
is not an identity or reusable resource name.

## Trust boundaries

The subject access token represents the authenticated user. The SPIRE
JWT-SVID actor token represents the attested requesting workload. PingFederate
must validate both before the custom plugin derives `AgentID` and issues a
signed token. The capability probe is not allowed to omit or weaken either
processor in a successful issuance test.

The token endpoint is accepted only when its Docker-published runtime port
matches the random clean-bootstrap container. This prevents the probe from
targeting the fixed normal workbench container. TLS is validated with the
exact isolated runtime certificate.

Probe output crosses from the sensitive token-exchange boundary into developer
evidence. It therefore contains only status, bounded OAuth error code, response
field presence, token type metadata, verified JOSE metadata, and claim names.
Claim values and compact tokens do not cross that boundary.

## Sanitized probe results

| Probe | Result | Interpretation |
| --- | --- | --- |
| Current access-token profile, `audience=mcp-gateway` | HTTP 200; verified RS256 JWT; `typ=at+jwt`; issued type is access token; token type is `Bearer`; no refresh token | Positive control proves the isolated TEPP, subject processor, actor processor, ATM, and signing path are functional |
| Missing actor token | HTTP 400 `invalid_request`; no token | Required actor validation fails closed |
| Txn-Token requested type, existing audience | HTTP 400 `invalid_request`; no token | Rejection is independent of trust-domain audience configuration |
| Access-token requested type, `audience=example.org` | HTTP 200; verified current-profile JWT | The isolated trust-domain audience selector resolves successfully; audience resolution is not the Txn-Token-type blocker |
| Txn-Token requested type, `audience=example.org` | HTTP 400 `invalid_request`; no token | PingFederate 13.1 rejects the Txn-Token requested type even when the audience resolves |
| Current profile plus `request_context` and `request_details` | HTTP 200; verified current-profile JWT; claim-name set unchanged | PingFederate accepts the extra form parameters, but the current TEPP/ATM does not propagate them. Accessibility to a supported custom mapping remains unproven |

The positive responses contained `expires_in` and did not contain a response
`scope` or refresh token. Their verified claim names were:

```text
agent_id
agent_instance_id
aud
exp
iat
iss
jti
nbf
scope
sub
transaction_id
transaction_purpose
workload_id
```

No claim values were recorded by the capability evidence.

## SDK evidence

Inspection of the extracted 13.1 `pingfederate-sdk.jar` shows:

```text
BearerAccessTokenManagementPlugin.TOKEN_TYPE = "Bearer"
BearerAccessTokenManagementPlugin.issueAccessToken(...) -> IssuedAccessToken
IssuedAccessToken(value, tokenType, expiresAt)
```

The repository's plugin currently returns `new IssuedAccessToken(...,
"Bearer", ...)`. Although that constructor accepts a string, the SDK plugin
contract itself is a bearer access-token manager and publishes the fixed
`Bearer` token type constant. Combined with both live `invalid_request`
results, there is no evidence that the ATM path can register the Transaction
Token output URN or make PingFederate return `token_type=N_A`.

The SDK also exposes a general WS-Trust `TokenGenerator`, but Task 34 found no
evidence that registering one makes the OAuth token-exchange endpoint accept
the draft-11 Txn-Token URN or outer response semantics. That path remains an
investigation item and must not be assumed safe or supported.

## Capability decision

Full native draft-11 wire-profile support is not available through the current
PingFederate 13.1 bearer ATM configuration.

Confirmed native capabilities:

- RFC 8693 subject and actor token exchange;
- exact subject/actor processor mapping;
- trust-domain-shaped audience selection when configured;
- custom signed JWT headers and claims inside the ATM plugin;
- exact short lifetime, managed signing key, and JWKS verification;
- strict missing/tampered actor rejection.

Confirmed native blockers:

- the Txn-Token requested type URN is rejected;
- the successful outer response identifies an OAuth access token;
- the ATM path returns `Bearer`, not `N_A`;
- current context parameters do not reach the issued claim set.

## Recommendation

Do not weaken the request to access-token type and call the result conformant.
Do not make workloads auto-detect an `at+jwt` bearer token as a Txn-Token.

Recommended order:

1. Document PingFederate 13.1 outer-wire non-conformance and request/track a
   PingFederate enhancement for the Transaction Token URN and response.
2. Continue with the strict draft-11 domain model and verifier offline, with
   normal runtime remaining in legacy mode.
3. Update the existing PingFederate signer to emit the draft-11 inner JWT only
   after the new verifier and negative tests exist.
4. Investigate the supported token-generator SDK path in another isolated
   capability task before considering an adapter.
5. If exact interoperability is required and no native path exists, design a
   narrow non-signing TTS protocol adapter under a separate ADR and threat
   model. It may translate only the outer protocol, must authenticate the
   requester with SPIFFE mTLS, must independently verify the PingFederate-signed
   JWT, and must never sign or rewrite it.
6. Stop the migration if exact support requires a second signer, token
   rewriting, subject/actor disclosure, or weakened identity validation.

Task 34 does not approve an adapter and does not claim draft-11 conformance.

## Remaining unknowns

- Whether a supported custom OAuth token generator can register the Txn-Token
  URN in PingFederate 13.1.
- Whether a supported extension can produce `token_type=N_A` and the exact
  `issued_token_type` without an outer adapter.
- Whether `request_context` and `request_details` can be obtained through a
  supported TEPP, datastore, authorization-details, or plugin API without
  trusting caller values directly.
- Whether PingFederate can authenticate the requesting workload with SPIFFE
  mTLS or another asymmetric client method while retaining the separate actor
  JWT-SVID binding.
- Product behavior for cluster-wide registration and upgrade of any custom
  token type.

Each unknown requires isolated evidence. None permits relaxed issuer,
audience, algorithm, key ID, time, subject, actor, or workload binding.

## Files and commands

Primary implementation files:

- `deploy/pingfederate/scripts/probe_transaction_tokens_capabilities.py`
- `scripts/test-pingfederate-clean-bootstrap.ps1`
- `deploy/pingfederate/terraform/transaction_tokens_capability_probe.tf`
- `deploy/pingfederate/terraform/variables.tf`
- `deploy/pingfederate/launcher_test.go`
- `Makefile`

Run the complete isolated gate with:

```powershell
make pf-probe-txn-profile
```

The opt-in trust-domain selector defaults to disabled and is enabled only in
the random clean-bootstrap Terraform state when the capability switch is set.
It is never created by the normal workbench apply.
