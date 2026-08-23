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
