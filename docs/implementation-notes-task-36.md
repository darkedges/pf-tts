# Implementation Notes: Task 36

## Acceptance criteria implemented

The PingFederate custom Access Token Manager now has two explicit modes:

- `legacy-wai-jwt`, which preserves the existing `typ=at+jwt` and legacy
  claim shape;
- `ietf-txn-token-v11`, which emits the strict inner Transaction Token JWT.

There is no automatic format detection or fallback. Terraform defaults to the
legacy mode. The strict mode is allowed only when the isolated capability gate
is also enabled and is exercised with `make pf-test-txn-inner`.

## Strict inner profile

The isolated strict profile emits exactly these top-level claims:

```text
iss sub aud iat exp jti txn scope req_wl tctx
```

The protected header is exactly the configured RS256 signing metadata plus
`typ=txntoken+jwt`. `aud` is the SPIFFE Trust Domain `example.org`. The local
context is:

```text
tctx.wai.version
tctx.wai.agent.id
tctx.wai.agent.instance_id
tctx.wai.agent.workload_id
tctx.wai.target
tctx.wai.tool
```

No legacy `agent_id`, `agent_instance_id`, `workload_id`, `transaction_id`, or
`transaction_purpose` top-level claims are emitted in strict mode.

## Trust boundaries

The subject comes only from the validated subject-token processor. The
requesting workload comes only from the validated SPIRE actor JWT-SVID. The
logical agent is derived from the plugin's copied trusted SPIFFE-to-AgentID
configuration. Agent instance and transaction identifiers are minted inside
the plugin.

Strict target `demo`, tool `system.whoami`, and scope
`mcp.system.whoami` are fixed plugin/Terraform configuration. The plugin
rejects an exchange scope that does not exactly match the configured narrow
scope. It does not consume `request_context`, `request_details`, caller JSON,
or caller-supplied AgentID values.

PingFederate's ATM selection field accepts only absolute resource URIs, so it
retains the existing `urn:wai:mcp-gateway` selector. The strict exchange uses
the isolated `example.org` OAuth resource client, and the plugin independently
mints and signs `aud=example.org`. Treating the bare Trust Domain as an ATM
resource URI was tested and rejected by PingFederate with HTTP 422; validation
was not relaxed to bypass that product constraint.

The same PingFederate-managed RSA signing key is used in both modes. There is
no secondary signer, signature rewriting, or decode-and-resign component.

## Failure coverage

Automated tests reject:

- missing, unknown, or automatic profile selection;
- requested scope expansion;
- missing verified subject or workload attributes;
- forged or unbound logical agents and workload conflicts;
- malformed or line-breaking fixed context;
- wrong JOSE type, algorithm, key, signature, issuer, audience, lifetime, or
  strict claim shape through the Go verifier and live verifier matrix;
- legacy claim leakage into strict output;
- disabled TLS validation in scope provisioning and live exchange evidence;
- enabling the strict Terraform profile without the isolated capability gate;
- mutable or caller-derived strict target, tool, scope, and audience fields.

## Live evidence

On 24 August 2026, `make pf-test-txn-inner` completed successfully against the
digest-pinned PingFederate 13.1 image in random container
`wai-pf-clean-4b92d154a24390a5`.

The gate:

1. built and unit-tested the plugin;
2. provisioned both legacy and strict scopes without replacing other server
   settings;
3. applied 20 resources in isolated Terraform state;
4. rejected a tampered SPIRE actor JWT-SVID;
5. completed RFC 8693 subject/actor exchange;
6. verified the issued JWT signature against exactly one managed JWKS key;
7. verified the exact strict header, claim names, values, context schema,
   20-second lifetime, workload agreement, and absence of legacy claims; and
8. removed the exact container, volume, certificate, and isolated state.

No compact subject, actor, or transaction token was printed or persisted by
the evidence output.

## Remaining non-conformance

Task 36 changes only the inner signed JWT. PingFederate still requires the
OAuth access-token requested type and returns the token through an outer
Bearer/access-token response. It does not return the draft Transaction Token
requested/issued URN or `token_type=N_A`.

The repository therefore still does not claim draft-11 conformance. Phase D
must follow the Task 34 decision and must stop if exact outer behavior would
require another signer, token rewriting, or weaker subject/actor validation.

Application middleware and Call Chain transport remain legacy and do not yet
accept this strict token.
