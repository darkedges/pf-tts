# Transaction Tokens alignment review and migration plan

## Review status

- Review date: 24 August 2026
- Base specification: [draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11), published 30 July 2026
- Agent extension reviewed separately: [draft-oauth-transaction-tokens-for-agents-06](https://datatracker.ietf.org/doc/html/draft-oauth-transaction-tokens-for-agents-06), published 11 April 2026
- Reference implementation: [CNCF Tokenetes](https://www.cncf.io/projects/tokenetes/) and its [example application](https://github.com/tokenetes/example-application)
- Product baseline: PingFederate 13.1 and PingAuthorize 11.1

Both specifications are Internet-Drafts and may change, be replaced, or expire.
The base draft is an OAuth working-group document. The agent extension is a
separate individual draft and is not a base Transaction Tokens requirement.
This repository does not currently claim compatibility or conformance with
either document or with Tokenetes.

Task 33 is review-only. This document does not authorize or make runtime,
product, policy, token, or transport changes.

## Executive conclusion

The implementation is close to the Transaction Tokens architecture but not to
the complete wire profile.

The strongest existing alignment is architectural:

- PingFederate is already the single logical issuer for local transaction
  context.
- The external user access token stops at the exchange boundary.
- The agent workload presents independently verified SPIRE identity evidence.
- The issued JWT has a short, exact lifetime and immutable propagation.
- Every protected workload validates the JWT and independently authenticates
  the immediate SPIFFE mTLS caller.
- PingAuthorize or OPA receives typed, verified context rather than raw token
  input.
- One transaction identifier is correlated across the Call Chain without
  logging raw credentials.

The largest conformance gaps are protocol-level:

- PingFederate is requested to issue an OAuth access token, not a Txn-Token.
- The JOSE `typ` is `at+jwt`, not `txntoken+jwt`.
- The response is `Bearer` with an access-token `issued_token_type`, not `N_A`
  with the Transaction Token type URN.
- The JWT uses application claims instead of `txn`, trust-domain `aud`,
  `tctx`, `rctx`, and `req_wl`.
- Internal HTTP calls use `Authorization: Bearer`, not the dedicated
  `Txn-Token` header.
- The token exchange client uses a shared secret rather than asymmetric
  requester authentication.

The closest safely achievable target is a strict Transaction Tokens mode in
which PingFederate remains the logical Transaction Token Service and the only
signer and issuance-policy authority, SPIFFE mTLS
authenticates the requester and every workload hop, the custom PingFederate
plugin emits the standard JWT shape, and all internal workloads accept exactly
one `Txn-Token` header. Full wire conformance depends on whether PingFederate
can register the Transaction Token output type and return the required outer
OAuth response. Official PingFederate documentation lists only access token,
SAML 1, SAML 2, and JWT token-exchange output types. That limitation must be
proven against PingFederate 13.1 before implementation begins.

## Trust model being preserved

The Transaction Tokens base draft says a Txn-Token conveys authorization
context and must not be used as a workload authentication credential or as an
OAuth access token. This matches the repository's separation:

```text
Txn-Token                    SPIFFE mTLS                 Policy
--------------------------   -------------------------   -------------------
immutable user, agent,       immediate network caller   target, tool, scope,
transaction, and purpose     for this exact hop          and caller decision
```

Authorization remains the conjunction of all three. A valid Txn-Token alone
does not authorize a request.

The following identities remain separate:

- `UserID`: principal represented by the validated external subject token
- `AgentID`: logical agent derived from trusted workload-to-agent policy
- `AgentInstanceID`: one execution, minted at the TTS boundary
- `SPIFFEID`: cryptographically attested workload identity
- `TransactionID`: unique identifier for the transaction and complete Call Chain

No migration may derive `AgentID`, `SPIFFEID`, requester identity, target, or
user identity from untrusted request JSON.

## Requirement matrix

Status values are `implemented`, `partial`, `missing`, `intentional
difference`, `product investigation`, and `unsupported by documented product`.

| Area | Draft 11 target | Current status | Evidence and required action |
| --- | --- | --- | --- |
| Logical TTS | Exactly one logical TTS per Trust Domain | Partial | PingFederate is the only transaction JWT signer in `deploy/pingfederate/plugins` and Terraform. Define the whole PingFederate deployment, including any required protocol adapter, as one logical TTS. |
| External invocation | Exchange external authorization before internal calls | Implemented | `pkg/agent/agent.go` exchanges the browser/user access token before calling the gateway. |
| RFC 8693 grant | `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` | Implemented | `pkg/pingfederate/exchange.go`; exact-form coverage in `TestExchangeSendsExactFormAndCredentials`. |
| Trust Domain audience request | Required `audience` is the Trust Domain | Missing | Current exchange audience selects `mcp-gateway`; see `config/example.yaml` and `deploy/pingfederate/terraform/variables.tf`. Migrate to `example.org` only after target authority is moved into verified context and policy. |
| Narrow transaction scope | Required `scope` represents purpose or intent | Partial | Current `mcp:invoke` is enforced but broad; `transaction_purpose` is separate. Define a bounded scope vocabulary that cannot expand the subject token's authority. |
| Subject token | Required and type identified by URI | Implemented | User access token and access-token type are sent by `pkg/pingfederate/exchange.go`; PingFederate TEPP validates it in `token_exchange_policy.tf`. |
| Subject signature and status | Signed tokens validated before claims are used | Implemented for current user ATM | Subject token processor maps only validated contract attributes. Live negative coverage includes bad credentials and tampered exchange inputs. Document revocation/introspection behavior for all future subject types. |
| Refresh token input | Must not be accepted | Partial | Client always sends access-token type. Add explicit client and TTS tests rejecting refresh-token type before claiming conformance. |
| Requester proof | TTS and requester mutually authenticate | Partial | HTTPS authenticates PingFederate; OAuth client secret authenticates the client, and the actor JWT-SVID proves workload identity. Target state is SPIFFE mTLS or asymmetric client authentication without weakening actor validation. |
| Actor token | Not required by base profile | Intentional difference | `actor_token` is a SPIRE JWT-SVID required by the TEPP. Preserve it as explicit agent workload evidence. Do not describe it as a base-profile requirement. |
| Request context | `request_context` is recommended and TTS-authoritative | Missing | Current client sends no parameter. Prefer a minimal verified authentication-method value or a documented privacy-based omission. Never copy arbitrary browser headers. |
| Request details | `request_details` is recommended and TTS-authoritative | Missing | Current purpose/tool are not transmitted as this parameter. Permit only an exact server-selected schema and let PingFederate policy derive or approve `tctx`. |
| Requested type | `urn:ietf:params:oauth:token-type:txn_token` required | Unsupported by documented product, pending proof | `pkg/pingfederate/exchange.go` hard-codes access-token type. PingFederate documentation lists four supported output types and does not list Txn-Token. Run a bounded 13.1 capability spike. |
| Response type | `issued_token_type` is Txn-Token URN | Missing | Current client and PingFederate return access-token type. Capability gate shares the requested-type blocker. |
| Response token type | `token_type` is `N_A` | Missing | Custom ATM returns `Bearer` in `ExactTtlJwtAccessTokenManager.java`. Changing the plugin may not control the outer PingFederate response; prove separately. |
| No refresh token | Response must omit `refresh_token` | Implemented in observed flow | Current response model has no refresh token. Add strict response decoding and a negative server test that rejects a refresh token. |
| JOSE type | Protected `typ` is exactly `txntoken+jwt` | Missing, locally implementable | `TransactionJwtIssuer.java` emits `at+jwt`. Custom plugin can change this; Go verifier must explicitly require it. |
| Algorithm | Locally allowlisted, never header-selected | Implemented | Issuer fixes RS256; `pkg/pingfederate/verifier.go` parses with configured algorithms. Tests reject disallowed algorithms. Retain this stricter local rule. |
| Key ID and rotation | `kid` recommended; reliable signing-key determination | Implemented with limits | Issuer emits `kid`; verifier requires one exact JWKS match. Rotation JWKS tests exist. Document cache/refresh behavior and overlapping keys before production. |
| `iat` and `exp` | Required and valid | Implemented | Java plugin emits both with 1-60 second lifetime; Go verifier validates with bounded skew. |
| `aud` | Required Trust Domain | Partial | Strict resource audience is currently validated. Change value only with simultaneous target-policy migration. |
| `txn` | Required unique transaction identifier | Partial | `transaction_id` is unique and immutable, but claim name is non-standard. Map directly to scalar `txn`; retain separate optional `jti`. |
| `sub` | Required principal unique in Trust Domain | Implemented in shape, identity semantics need review | Current `sub` is the verified user. Define pairwise or stable identifier policy and prove uniqueness in `example.org`; do not expose a login name by accident. |
| `scope` | Required TTS-determined narrow intent | Partial | Present, but currently inherited from the subject path and paired with a custom purpose. TTS must prevent scope expansion and determine final value. |
| `tctx` | Recommended immutable transaction context object | Missing | Introduce a versioned, bounded object containing approved target/tool and agent context. Reject wrong types, duplicate semantic fields, conflicts, and oversized data. |
| `rctx` | Recommended environmental request context | Missing by design today | Add only data the TTS can verify and downstream policy needs. Omit IP/User-Agent by default to reduce PII and spoofing risk. |
| `req_wl` | Required requesting workload | Partial | Current `workload_id` contains the actor SPIFFE ID. Map verified actor subject to scalar `req_wl`; never source it from `request_details`. |
| Additional claims | Recipients ignore unknown top-level claims | Partial | Go JSON decoding already ignores unknown claims. Require the local `tctx.wai` profile without rejecting unrelated future top-level claims. Reject conflicts between standard and local semantic fields. |
| Dedicated HTTP field | Exactly one `Txn-Token` field | Missing | Agent, middleware, gateway, MCP server, and API currently use `Authorization: Bearer`. Implement strict configured mode and reject zero, duplicate, comma-joined, or simultaneous legacy candidates. |
| Independent validation | Every receiving workload validates token | Implemented | `pkg/middleware/identity.go` verifies before creating typed identity context. Expand verifier for standard header and claims. |
| Immediate caller | Txn-Token not used as authentication credential | Implemented | SPIFFE X.509-SVID mTLS and exact caller policy are independent of JWT claims. Coverage in middleware and end-to-end tests. |
| Immutable propagation | Same token throughout Call Chain | Implemented | Gateway and MCP server forward the verified compact token. Token fingerprint evidence and transaction correlation prove sameness without logging raw tokens. |
| Replay | Short lifetime; not replay-proof | Partial | Exact 20-second local token is strong. No replay cache or proof of possession is claimed. Keep these optional until a concrete threat and distributed cost model exists. |
| Invalidation | TTS policy addresses invalidated subject credentials | Product investigation | Determine PingFederate revocation/introspection behavior and whether issued Txn-Tokens need early invalidation policy. Do not imply a 20-second JWT can be revoked unless implemented. |
| Cross-domain | Separate profile, not local MVP | Intentionally out of scope | The local Trust Domain is `example.org`. Do not accept foreign Txn-Tokens without a separately reviewed cross-domain design. |
| Policy decision | Downstream workloads authorize verified context | Implemented | `pkg/authorization` evaluates typed identity, transaction, scope, target, tool, and immediate caller. PingAuthorize remains PDP, not token verifier. |
| Logging and privacy | Avoid raw tokens and unnecessary PII | Implemented with extension work | `pkg/audit` stores an allowlisted fingerprint summary. Add bounded `tctx`/`rctx` audit views; keep raw Txn-Tokens prohibited. |
| Error handling | OAuth errors without credential disclosure | Implemented for current client | Exchange client reports status and code only. Add profile-specific invalid request/type/context cases. |

## Claim mapping

The proposed mapping preserves the five identity dimensions rather than
flattening them into `sub` or `req_wl`.

| Current value | Proposed Txn-Token location | Authority | Sensitivity and validation |
| --- | --- | --- | --- |
| `UserID` / current `sub` | `sub` | Validated subject token plus TTS policy | Required, bounded, unique within Trust Domain; potentially PII; never caller JSON |
| `TransactionID` / `transaction_id` | `txn` | TTS CSPRNG/UUID generation | Required scalar, unique, immutable; safe correlation identifier |
| Current `JWTID` | optional `jti` | TTS | Keep separate from `txn`; never use `jti` as business transaction identity |
| Current transaction audience | `aud=example.org` | TTS configuration | Exact Trust Domain; not a caller-selected target |
| `Purpose` plus current scopes | `scope` | TTS policy | Required narrow intent; must not exceed subject authority |
| `SPIFFEID` of exchange requester | `req_wl` | Validated actor JWT-SVID | Required, exact SPIFFE ID; not the immediate caller at later hops |
| `AgentID` | `tctx.wai.agent.id` | Trusted SPIFFEID-to-AgentID mapping | Required by local agent profile; caller assertion prohibited |
| `AgentInstanceID` | `tctx.wai.agent.instance_id` | TTS | Required by local agent profile, unique and bounded |
| Original workload SPIFFE ID | `tctx.wai.agent.workload_id` and `req_wl` | Validated actor JWT-SVID | Values must agree exactly; conflict rejects issuance and validation |
| MCP target | `tctx.wai.target` | TTS policy from allowlisted request details | Must match the actual protected route at authorization time |
| MCP tool | `tctx.wai.tool` | Server-selected/validated request details plus TTS policy | Exact bounded identifier; untrusted tool arguments excluded |
| Authentication method | optional `rctx.authn` | Subject processor/TTS | Include only a verified method identifier; never copy a browser assertion |
| Source IP/User-Agent | omitted initially | None | PII and proxy-spoofing risk outweigh current policy value |

Example target payload for planning, not an implemented contract:

```json
{
  "iss": "https://pingfederate.example/tts",
  "iat": 0,
  "exp": 0,
  "aud": "example.org",
  "txn": "019...",
  "sub": "pairwise-user-123",
  "scope": "mcp.system.whoami",
  "req_wl": "spiffe://example.org/agent/web-app",
  "tctx": {
    "wai": {
      "version": 1,
      "agent": {
        "id": "urn:agent:web-app",
        "instance_id": "019...",
        "workload_id": "spiffe://example.org/agent/web-app"
      },
      "target": "demo",
      "tool": "system.whoami"
    }
  },
  "rctx": {
    "authn": "pwd"
  },
  "jti": "019..."
}
```

The verifier should ignore unknown top-level claims as required by the draft,
but must require and exactly validate every claim in the configured local WAI
profile. An unknown top-level claim cannot override or conflict with a known
semantic field.

## PingFederate capability review

### Confirmed capabilities

PingFederate supports RFC 8693 token exchange, required subject and optional
actor tokens, TEPP attribute mapping, ATM selection, and custom token
processors/managers. Official documentation confirms actor-token mappings and
describes `requested_token_type`, `issued_token_type`, and `token_type` in the
exchange flow.

The repository's custom ATM already controls:

- the signed JWT claims;
- the protected `typ`, `alg`, and `kid` headers;
- exact seconds-level expiry;
- trusted workload-to-agent binding;
- TTS-generated agent instance and transaction identifiers.

Therefore the custom plugin can implement the inner Txn-Token JWT shape without
adding a new signer or rewriting an already signed token.

### Capability blockers requiring proof

The [PingFederate token exchange documentation](https://docs.pingidentity.com/pingfederate/13.0/introduction_to_pingfederate/pf_token_exchange_grant.html)
lists only access token, SAML 1, SAML 2, and JWT as supported requested output
types. It does not list
`urn:ietf:params:oauth:token-type:txn_token`. The current ATM SDK returns an
`IssuedAccessToken`, and the plugin currently reports `Bearer`.

Before changing production code, a PingFederate 13.1 capability spike must
answer independently:

1. Can a custom ATM or token generator register the Txn-Token output type URN?
2. Will `/as/token.oauth2` accept that URN in `requested_token_type`?
3. Can the outer response emit `issued_token_type=...:txn_token`?
4. Can the outer response emit `token_type=N_A`?
5. Can `request_context` and `request_details` reach a trusted mapping or custom
   plugin without treating their contents as verified?
6. Can the OAuth client authenticate asymmetrically or with SPIFFE-compatible
   mTLS while the actor JWT-SVID remains separately validated?
7. Can one logical TTS remain available through supported clustering and key
   rotation behavior?

Evidence must be a reproducible request against the pinned local image,
discovered plugin/SDK descriptors, or exact Ping documentation. A guessed
configuration is not evidence.

### Safe fallback if PingFederate cannot emit the outer profile

Preferred outcomes, in order:

1. Use supported PingFederate configuration or a supported custom token
   generator interface that emits the exact profile.
2. Request a PingFederate product enhancement and document the remaining
   non-conformance while retaining the secure current architecture.
3. If exact wire compatibility is required, consider a narrow TTS protocol
   adapter only after a dedicated ADR and threat model.
4. Stop the conformance migration if the adapter would weaken identity binding
   or expose subject/actor tokens.

A permitted adapter would authenticate the workload with SPIFFE mTLS, validate
the exact request schema, call only the fixed PingFederate HTTPS endpoint, and
return only a PingFederate-signed JWT after independent verification. It may
translate the outer request/response fields but must never sign, rewrite, or
decode-and-resign the Txn-Token. It must be treated as part of the single
logical TTS, have no general proxy capability, and never log token bodies.

## SPIRE actor and agent extension review

In the base draft, the requesting workload proves its identity through mutual
authentication to the TTS. An RFC 8693 `actor_token` is not required by the
base Transaction Tokens request.

The local actor JWT-SVID currently serves two related roles:

- cryptographic evidence of the requesting agent workload; and
- an RFC 8693 actor token used by PingFederate's TEPP to derive the logical
  agent binding.

It does not replace mutual requester authentication because possession of a
bearer JWT-SVID and OAuth client secret is not equivalent to channel-bound
workload authentication. The target should use SPIFFE mTLS or another
asymmetric client authentication method to satisfy the base TTS boundary while
retaining the actor token for explicit agent semantics.

The agent extension revision 06 describes an `act` claim derived from verified
agent/client evidence. It does not define the repository's current
`agent_id`/`agent_instance_id` schema and does not use `actor_token` in its
base flow. Until that draft stabilizes, the local agent context should be a
versioned WAI profile inside `tctx`. A later task can map it to `act` only after
an explicit compatibility review. Experimental agent claims must never be
presented as base Transaction Tokens conformance.

## Audience and authority migration

Changing `aud` from `urn:wai:mcp-gateway` to `example.org` increases the set of
workloads for which the token is syntactically intended. That is an
authorization-sensitive migration, not a string rename.

Before cutover:

- `scope` must express the narrow transaction intent;
- `tctx.wai.target` and `tctx.wai.tool` must be TTS-approved;
- each workload must compare its actual route and operation to `tctx`;
- immediate-caller SPIFFE policy must remain exact for every hop;
- PingAuthorize/OPA must require the complete tuple;
- a token valid for the Trust Domain but intended for another target must deny;
- fan-out must be explicitly allowed by policy rather than inferred from `aud`.

Failure case: a valid Txn-Token for `demo/system.whoami` presented to another
service in `example.org` must fail even though its trust-domain audience is
valid.

## HTTP transport migration

The base draft requires exactly one `Txn-Token` HTTP field and prohibits use of
the OAuth `Authorization` field for Txn-Token propagation.

All of these paths require an atomic update:

- `pkg/agent/agent.go`: send one `Txn-Token` field;
- `pkg/middleware/identity.go`: extract exactly one field before verification;
- `pkg/mcp/gateway.go`: preserve the verified compact value;
- `pkg/mcp/server.go`: forward one `Txn-Token` field to the API;
- command wiring and Compose proxy configuration: allow but never log the field;
- browser/UI audit: show only allowlisted verified claim evidence;
- MCP Streamable HTTP: retain standard MCP headers independently.

Go's `http.Header.Get` can hide duplicate-field ambiguity. Extraction must
inspect the complete `Header.Values("Txn-Token")` collection and reject:

- no field;
- more than one field line;
- a comma-joined value;
- whitespace, empty, or oversized values;
- simultaneous `Txn-Token` and legacy transaction bearer credentials;
- a Txn-Token placed in a query, cookie, body field, or MCP argument.

The `Authorization` field remains available for unrelated OAuth access tokens
on endpoints that genuinely require them, but protected internal routes in
Txn-Token mode must not interpret it as transaction context.

## PingAuthorize and OPA migration

PingAuthorize and OPA remain policy decision points. They do not receive raw
Txn-Tokens and do not replace JWS, trust-domain audience, expiry, schema, or
SPIFFE caller validation.

The PEP should map a verified Txn-Token to the existing typed
`identity.RequestIdentityContext`, then add exact target/tool values from the
trusted route. Policy input should remain:

- verified `sub` as `user_id`;
- verified WAI agent ID and instance ID from `tctx`;
- verified `req_wl` and WAI workload agreement;
- authenticated immediate caller SPIFFE ID;
- verified `txn`, `scope`, target, and tool.

PingAuthorize's JSON PDP endpoint supports typed request attributes and returns
decisions plus statements/obligations. The existing adapter already denies
malformed, contradictory, unavailable, or obligation-bearing responses.
Preserve that behavior.

PingAuthorize decision logging needs explicit review because its optional
decision response views can log request and attribute values. The local profile
must keep full request/attribute views disabled and must not enable raw
Txn-Token header mapping. Only the PEP's allowlisted typed attributes should
cross the PDP boundary.

## Privacy and audit

`tctx` and `rctx` are signed but not encrypted. Every receiving workload can
read them. Inclusion is therefore a disclosure decision.

Rules:

- do not put the original subject token, actor JWT-SVID, Txn-Token, cookies,
  secrets, authorization codes, private keys, or refresh tokens in any claim;
- do not include sensitive MCP tool arguments in `tctx`;
- omit source IP and User-Agent until a reviewed policy requires them;
- use a stable pairwise user identifier where possible, not a display name;
- cap total token and individual context sizes before parsing into policy;
- keep the current non-replayable SHA-256 fingerprint evidence;
- rename evidence kind to a versioned `txn_token` value only at cutover;
- expose only allowlisted verified claims in the browser audit UI;
- reject credential-shaped and unknown audit fields;
- never configure PingAuthorize to log the raw PDP request if it could contain
  sensitive context.

## Compatibility strategy

Do not make one protected route auto-detect both formats.

Recommended strategy:

1. Add a configuration enum with two strict values: `legacy-wai-jwt` and
   `ietf-txn-token-v11`.
2. Build and test the new issuer/verifier/transport offline while local runtime
   remains in legacy mode.
3. Start a separately addressed test stack in strict Txn-Token mode.
4. Prove the complete allow/deny matrix and clean bootstrap there.
5. Cut the local application stack atomically to strict Txn-Token mode.
6. Reject `Authorization: Bearer` transaction presentation immediately after
   cutover.
7. Keep rollback as a complete configuration rollback to the legacy stack,
   never as dual acceptance on one route.

Token shape, transport header, audience semantics, and policy input must switch
together. Partial deployment could either lock out valid calls or broaden
authority.

## Conformance test plan

### TTS request and response

Positive test:

- mutual requester/TTS authentication succeeds;
- exact RFC 8693 form contains the Trust Domain, narrow scope, subject token,
  subject type, Txn-Token requested type, and bounded optional context;
- response is no-store, contains one signed JWT, returns `N_A`, returns the
  Txn-Token issued type, and contains no refresh token.

Failure tests:

- missing or wrong Trust Domain;
- missing, empty, duplicate, or authority-expanding scope;
- expired, malformed, refresh, wrong-issuer, wrong-audience, or invalid-signature
  subject token;
- missing actor evidence, wrong JWT-SVID audience, unknown key ID, disallowed
  algorithm, ambiguous SPIRE authority, or unbound actor workload;
- caller-authenticated workload and actor JWT-SVID workload conflict;
- unknown requested token type or access-token requested type;
- malformed, duplicate-key, oversized, or unapproved request context/details;
- response reports Bearer, access-token type, refresh token, ambiguous JSON, or
  a JWT that fails independent verification;
- any error includes a subject token, actor token, secret, or response body.

### JWT format and validation

Positive test:

- exactly one protected header with `typ=txntoken+jwt`, allowlisted `alg`, and
  one known `kid`;
- valid `iat`, `exp`, Trust Domain `aud`, unique `txn`, unique-in-domain `sub`,
  narrow `scope`, exact `req_wl`, and valid local `tctx.wai` profile;
- optional `iss` remains required by local policy and is allowlisted;
- the same compact JWT fingerprint appears at every Call Chain hop.

Failure tests:

- missing, wrong, duplicated, or unprotected `typ`;
- unsigned token, multiple signatures, disallowed algorithm, missing/unknown/
  duplicate key ID, wrong signature, stale JWKS, or ambiguous issuer;
- missing, empty, wrong-type, duplicate-semantic, expired, future, oversized,
  or conflicting required claims;
- wrong Trust Domain, reused `txn` where uniqueness enforcement applies, empty
  subject, scope expansion, or unknown local WAI profile version;
- `req_wl` conflicts with WAI workload or trusted agent binding;
- caller tries to supply `AgentID`, workload, target, or user through an
  untrusted request field;
- unknown top-level claims do not alter authorization and are ignored as the
  base draft requires.

### HTTP and Call Chain

Positive test:

- exactly one `Txn-Token` field is accepted;
- every hop validates before use;
- SPIFFE mTLS authenticates the expected immediate caller;
- the token is forwarded byte-for-byte unchanged;
- target/tool/scope policy permits the exact tuple;
- one `txn` is visible in safe audit events at agent, gateway, MCP, API, and PDP.

Failure tests:

- zero, duplicate, comma-joined, empty, whitespace, or oversized fields;
- legacy bearer transaction token, query parameter, cookie, body, or MCP
  argument presentation;
- valid token over the wrong SPIFFE mTLS identity;
- valid trust-domain token presented to a different target or tool;
- direct agent-to-API call when only the MCP server is allowed;
- unapproved fan-out or authority broadening;
- audit or PDP sink unavailable after an allow decision;
- any captured output contains a raw subject, actor, Txn-Token, secret, or
  authorization material.

## Phased implementation backlog

These are proposed tasks after Task 33. Numbering should be added to `TASKS.md`
only after this review is accepted.

### Phase A: product capability gate

Objective: resolve the PingFederate outer-protocol blocker without changing
the normal workbench.

- inspect the pinned 13.1 SDK and descriptors for custom output token type
  registration;
- execute isolated requests for the Txn-Token requested type;
- test `N_A`, issued type, request context/details visibility, and asymmetric
  requester authentication;
- publish sanitized evidence and an ADR choosing supported configuration,
  product enhancement/documented non-conformance, narrow adapter, or stop.

Rollback: remove only the isolated test container, volume, and state.

### Phase B: strict domain model and verifier

Objective: model draft 11 independently of transport and PingFederate.

- add typed Txn-Token header/claims and bounded WAI `tctx` profile;
- require local allowlisted issuer even though base `iss` is optional;
- validate Trust Domain, time, transaction, subject, scope, requester workload,
  WAI bindings, and exact JOSE header;
- add strict configured modes with no auto-detection;
- keep existing production wiring in legacy mode.

Rollback: configuration remains legacy; new code is unreachable in normal flow.

### Phase C: PingFederate inner token profile

Objective: have the existing PingFederate signer emit the exact inner JWT.

- update the custom ATM claim contract and `typ`;
- map only verified/policy-approved values into standard claims;
- use Trust Domain audience and TTS-determined narrow scope;
- add `request_context`/`request_details` processing only where supported and
  bounded;
- update Terraform and clean-bootstrap/live exchange tests.

Rollback: deploy the previous versioned plugin and Terraform profile as one
unit. Never accept both JWT shapes in the same strict mode.

### Phase D: exact TTS wire response

Objective: satisfy requested type, issued type, response type, no-refresh, and
mutual requester authentication requirements.

- use the capability-gate decision;
- prefer native supported PingFederate behavior;
- if approved, add only the narrow non-signing protocol adapter described
  above;
- independently verify the PingFederate-signed JWT before returning it;
- add token-leak, rogue-TTS, wrong-workload, and outer-response negative tests.

Blocker: stop here if exact behavior requires a custom signer, token rewriting,
or weakened PingFederate validation.

### Phase E: atomic Call Chain transport and policy cutover

Objective: switch all internal workloads to strict `Txn-Token` transport and
trust-domain authorization.

- update every sender and receiver together;
- move target/tool constraints into TTS-approved context and policy;
- update PingAuthorize/OPA typed inputs and package;
- enforce exact one-header handling and legacy bearer rejection;
- run unit, integration, clean-bootstrap, live browser, and full negative tests
  in a separately addressed stack before cutover.

Rollback: return the complete stack to legacy mode. Do not enable dual parsing.

### Phase F: conformance evidence and optional extensions

Objective: state the achieved profile precisely.

- publish a version-pinned conformance matrix and test evidence;
- document remaining PingFederate deviations;
- review the agent `act` extension separately;
- separately evaluate internally initiated transactions, early invalidation,
  replacement tokens if reintroduced by a later draft, replay monitoring, and
  proof of possession.

Optional extensions must not delay or dilute base-profile validation.

## Definition of done for the future migration

The implementation may claim alignment with draft 11 only when:

- the exact request, response, JOSE header, standard claims, Trust Domain, and
  `Txn-Token` HTTP field are implemented;
- every receiving workload validates the token and independent SPIFFE caller;
- scope and target authority cannot expand during audience migration;
- the original user access token and actor evidence stop at the TTS;
- all required positive and negative tests pass in a clean isolated stack;
- raw credentials and Txn-Tokens are absent from product, application, PDP,
  audit, test, and error logs;
- any deviation is listed as a non-conformance rather than hidden behind a
  compatibility label.

If PingFederate cannot produce the required outer token type and response, the
closest safe result is architectural alignment plus a documented wire-profile
non-conformance, unless the narrow non-signing adapter passes its own security
review. Security validation must never be weakened to improve the conformance
score.

## Primary references

- [IETF Transaction Tokens draft 11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11)
- [Transaction Tokens for Agents draft 06](https://datatracker.ietf.org/doc/html/draft-oauth-transaction-tokens-for-agents-06)
- [CNCF Tokenetes project](https://www.cncf.io/projects/tokenetes/)
- [Tokenetes example application](https://github.com/tokenetes/example-application)
- [PingFederate token exchange grant](https://docs.pingidentity.com/pingfederate/13.0/introduction_to_pingfederate/pf_token_exchange_grant.html)
- [PingFederate token exchange processor policies](https://docs.pingidentity.com/pingfederate/12.2/administrators_reference_guide/pf_defining_token_exchange_processor_policies.html)
- [PingFederate OAuth grant type parameters](https://docs.pingidentity.com/pingfederate/12.3/developers_reference_guide/pf_oauth_grant_type_param.html)
- [PingAuthorize API reference](https://docs.pingidentity.com/pingauthorize/11.1/paz_api_reference.html)
- [PingAuthorize JSON PDP flow](https://docs.pingidentity.com/pingauthorize/10.3/pingauthorize_server_administration_guide/paz_json_pdp_api_flow.html)
- [PingAuthorize decision response logging](https://docs.pingidentity.com/pingauthorize/11.1/pingauthorize_server_administration_guide/paz_config_decision_response_view.html)
