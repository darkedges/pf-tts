# Workload Agent Identity — Bootstrap

A Go-first reference implementation for binding:

- human user identity,
- logical AI agent identity,
- runtime workload identity from SPIRE,
- short-lived transaction context minted by PingFederate,
- MCP requests and downstream service calls.

## MVP

The first vertical slice is:

User OAuth token → AI Agent → local SPIRE lab JWT-SVID → PingFederate RFC 8693 token exchange → short-lived transaction JWT → MCP Gateway → MCP Server → protected API.

The repository now includes a self-contained SPIRE lab under `deploy/spire/` using the official SPIRE Server/Agent images. This lets the identity side of the architecture be developed and tested before PingFederate is wired in.

Use SPIRE X.509-SVIDs and mTLS for immediate workload-to-workload authentication. Use the PingFederate-issued transaction JWT for immutable user/agent/transaction context.

## Transaction Tokens profile alignment

The architecture is intentionally close to the Transaction Tokens model
implemented by the [CNCF Tokenetes project](https://www.cncf.io/projects/tokenetes/).
In that model, a Transaction Token Service (TTS) converts an external
authorization into a short-lived signed Txn-Token. The token preserves
immutable identity and authorization context throughout an internal call
chain, while each workload still authenticates its immediate caller.

PingFederate fills the logical TTS role in this implementation. SPIRE provides
the requesting agent's workload evidence, PingFederate binds that verified
workload to an approved logical agent, and the resulting transaction JWT is
propagated unchanged through the MCP gateway, MCP server, and protected API.
SPIFFE X.509-SVID mTLS independently authenticates the caller at every hop.
PingAuthorize or OPA evaluates policy only after those identity checks.

The project does not yet claim conformance with the evolving
[IETF Transaction Tokens profile](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11).
Its current alignment is:

| Transaction Tokens property | Current status |
| --- | --- |
| RFC 8693 exchange at a logical TTS | Implemented with PingFederate |
| External user authorization stops at the TTS | Implemented; the original user token is not propagated downstream |
| Requesting workload is cryptographically authenticated | Implemented with a SPIRE JWT-SVID actor token and trusted workload-to-agent mapping |
| Short-lived signed transaction context | Implemented with a PingFederate-issued JWT |
| Immutable context across the internal call chain | Implemented and tested across agent, gateway, MCP server, and API |
| Immediate caller authenticated independently | Implemented with SPIFFE X.509-SVID mTLS |
| Unique transaction correlation across workloads | Implemented with `TransactionID` and structured audit events |
| Trust-domain audience and strict validation | Partially aligned; strict audience validation exists, but the current audience identifies a logical resource rather than the Transaction Tokens trust domain |
| `typ: txntoken+jwt` protected header | Not implemented |
| `requested_token_type` and `issued_token_type` set to `urn:ietf:params:oauth:token-type:txn_token` | Not implemented; the current exchange returns an OAuth access-token type |
| Standard `txn`, `scope`, `tctx`, `rctx`, and `req_wl` claims | Partially aligned through strongly typed application claims, but not yet encoded in the profile shape |
| Dedicated `Txn-Token` HTTP header | Not implemented; internal calls currently use bearer-token transport |
| Fail closed on the legacy token shape after migration | Not implemented; required before claiming profile conformance |

The SPIRE actor token is a deliberate agent integration in addition to the
base Transaction Tokens request. It keeps the user subject and requesting AI
agent workload separate at the TTS boundary. PingFederate must validate both
before deriving the logical `AgentID`; caller-supplied agent identity is never
authoritative.

Closing the remaining profile gaps must tighten validation rather than accept
both formats ambiguously. Migration requires explicit token-type and header
checks, exact standard claim validation, dedicated `Txn-Token` propagation,
updated PingFederate mappings, and failure tests that reject the legacy bearer
shape once the new profile is enabled.

The version-pinned requirement matrix, product capability blockers,
trust-boundary analysis, conformance tests, and phased migration backlog are in
[`docs/transaction-tokens-alignment-plan.md`](docs/transaction-tokens-alignment-plan.md).

## Non-goals for MVP

Do not build:

- a custom workload identity issuer,
- a custom transaction-token issuer,
- Kubernetes-specific core logic,
- transparent interception,
- a GUI,
- a general-purpose policy engine,
- long-lived transaction tokens.

## Key identity model

- `UserID`: human or upstream principal.
- `AgentID`: logical agent definition, for example `urn:agent:customer-support`.
- `AgentInstanceID`: one running/executing instance of that logical agent.
- `SPIFFEID`: attested runtime workload identity, for example `spiffe://example.org/agent/customer-support`.
- `TransactionID`: immutable ID created once for the delegated transaction.

A logical `AgentID` is never accepted from untrusted request input. It must be bound by configuration/policy to a verified SPIFFE identity.

## Start here

1. Read `AGENTS.md`.
2. Read `docs/architecture.md`.
3. Work through `TASKS.md` strictly in order.
4. Keep every milestone compiling and tested.


## Self-contained SPIRE lab

The SPIRE portion can run locally with Docker Compose.

```bash
./scripts/spire-lab-up.sh
./scripts/spire-register.sh
./scripts/spire-test-jwt.sh
```

The lab uses:

- SPIRE Server 1.15.2
- SPIRE Agent 1.15.2
- join-token node attestation for local bootstrap only
- Docker workload attestation
- Docker labels as workload selectors
- a shared Workload API socket volume
- separate SPIFFE IDs for the demo agent, MCP gateway, MCP server, and API

The join-token bootstrap is intentionally a **lab mechanism**, not a production recommendation.


## Terraform-managed PingFederate

PingFederate configuration is now modeled under:

```text
deploy/pingfederate/terraform/
```

The official `pingidentity/pingfederate` provider manages the token processors, Token Exchange Processor Policy, transaction token manager/mapping, and OAuth token-exchange client.

Plugin-specific field names are deliberately parameterized until the exact PingFederate 13.1 plugin descriptors are captured from the target lab server. This avoids baking guessed Admin API/plugin fields into the project.


## PingFederate plugin discovery

The PingFederate Terraform layer now includes an Admin API discovery phase:

```bash
make pf-discover
make pf-generate-tfvars
```

This queries the target PingFederate 13.1 server for the exact token processor
and Access Token Manager plugin descriptors before Terraform is allowed to
create plugin instances.

## Repository-owned Ping product profiles

The local Ping products start from pinned images plus read-only profile
overlays. Put only `PING_IDENTITY_DEVOPS_USER` and
`PING_IDENTITY_DEVOPS_KEY` in ignored `.env.local`; licenses and secrets are
retrieved or generated outside Git.

```bash
make pf-local-up
make pf-ensure-scope
make pf-apply
make pa-local-up
make pa-export-runtime-ca
```

`pf-local-up` first builds and tests the repository's custom PingFederate
plugin and creates ignored short-lived bootstrap TLS/system material when it
is absent. Both are placed in the read-only mounted profile. The administrator
password remains in `.env.local`; it is not written into the profile. On a clean named
volume, create the required scope and then apply the Terraform-managed product
configuration; keeping that second phase explicit prevents a startup command
from silently changing OAuth clients or secrets. `pa-local-up`
validates or creates the dedicated bridge network and configures the exact
repository-owned deployment package during first setup. The runtime
certificate export rejects a certificate that is not valid for the stable
`pingauthorize-wai` service identity.

On a clean checkout, the profile builder extracts only its four required
build-time JARs from the same digest-pinned PingFederate image. The ignored SDK
directory is populated automatically; no license, key, credential,
configuration, or state file is copied from the image.

Run `make pf-clean-bootstrap` to prove recreation in random test-owned ports,
volume, and Terraform state. The test validates both bootstrap and managed TLS,
performs the live token exchange and tampered-actor failure case, and removes
only its exact generated resources.

To capture an existing local PingFederate configuration for review, refresh
the runtime certificate and run the isolated bulk exporter:

```bash
make pf-export-ca
make pf-profile-export
```

The raw export, converter log, extracted environment values, and substituted
JSON are sensitive ignored files under
`deploy/pingfederate/generated/bulk-export`. The converter is digest-pinned and
has no network access. The generated candidate contains only exact allowlisted
WAI application resources and externalizes its five credential inputs to the
existing `TF_VAR_*` names. Nothing is copied into the trusted startup profile;
Terraform remains the authoritative configuration writer.

## Live local verification

After PingFederate Terraform has been applied and the SPIRE entries are
registered, export the current public PingFederate TLS certificate and start
the application workloads:

```bash
make pf-export-ca
make app-up
make lab-verify
```

`pf-export-ca` rejects expired, ambiguous, or incorrectly named certificates.
On Windows, `make pf-trust-local` additionally rejects CA or non-self-signed
certificates before trusting only the current PingFederate runtime leaf for the
current user. Review the Windows certificate prompt before accepting it.
The application containers mount the validated public certificate read-only;
they never disable TLS verification.

The live verification obtains the user token in memory and exercises the full
agent → gateway → MCP server → API path. Success requires the protected API to
observe the same immutable transaction ID as the MCP server. The same verified
transaction ID must also appear in structured audit events from the agent,
gateway, MCP server, and API. It also verifies
that forged logical identity, wrong audience, expired-token mode, an
unapproved MCP target, and a direct agent-to-API call are rejected without raw
tokens appearing in captured output.

## Trusted MCP authorization policy

The gateway compiles `config/authorization.rego` with OPA in-process from a
read-only container mount. Policy input contains only the typed, verified
AgentID, agent instance ID, transaction workload SPIFFE ID, purpose, scopes,
target, and tool. Undefined, non-boolean, timed-out, or failed decisions deny.
OPA network built-ins are disabled and structured decisions contain no bearer
material. The small authorization interface remains available for a future
PingAuthorize adapter.
