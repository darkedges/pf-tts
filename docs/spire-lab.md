# Self-contained SPIRE Lab

## Purpose

This directory provides a small SPIRE deployment for local product development.

It is not intended to be a production SPIRE deployment.

## Topology

- SPIRE Server
- SPIRE Agent
- Docker Workload Attestor
- shared Workload API socket
- Docker-label registration entries

Trust domain:

```text
example.org
```

Node SPIFFE ID pattern (derived by SPIRE from each fresh join token):

```text
spiffe://example.org/spire/agent/join_token/<one-time-token-id>
```

SPIRE 1.15.2 owns the reserved `/spire/agent/` namespace. Its join-token
attestor derives the node ID from the token, so callers cannot force the fixed
`spiffe://example.org/spire/agent/local-lab` value. The bootstrap writes only
the derived, non-secret parent ID to ignored generated material for the
registration script. It never writes the join token.

Workloads:

| Workload | Docker selector | SPIFFE ID |
|---|---|---|
| Demo agent | `docker:label:wai.workload:demo-agent` | `spiffe://example.org/agent/demo` |
| MCP gateway | `docker:label:wai.workload:mcp-gateway` | `spiffe://example.org/gateway/mcp` |
| MCP server | `docker:label:wai.workload:demo-mcp-server` | `spiffe://example.org/mcp/demo` |
| Demo API | `docker:label:wai.workload:demo-api` | `spiffe://example.org/api/demo` |
| Web application BFF | `docker:label:wai.workload:web-app` | `spiffe://example.org/agent/web-app` |
| Audit collector | `docker:label:wai.workload:audit-collector` | `spiffe://example.org/audit/collector` |

These registrations are created by `scripts/spire-register.sh` beneath the
single attested lab agent. Re-running the script is idempotent: an existing
SPIFFE ID is retained rather than duplicated.

The label is observed by the SPIRE Agent through Docker workload attestation.
A workload cannot select another identity by passing a SPIFFE ID to the
Workload API. In particular, do not put more than one of these labels on a
container and do not reuse one label for multiple registered SPIFFE IDs; either
case creates ambiguous identity and must be rejected.

### Registration examples

The effective registration pairs are:

```text
spiffe://example.org/agent/demo
  docker:label:wai.workload:demo-agent

spiffe://example.org/gateway/mcp
  docker:label:wai.workload:mcp-gateway

spiffe://example.org/mcp/demo
  docker:label:wai.workload:demo-mcp-server

spiffe://example.org/api/demo
  docker:label:wai.workload:demo-api
```

Inspect the registered entries without exposing SVID material:

```bash
docker compose -f deploy/spire/compose.yaml exec -T spire-server \
  /opt/spire/bin/spire-server entry show
```

For each application container, mount only the shared Workload API socket and
set its one expected `wai.workload` label. The application must additionally
select its exact expected SPIFFE ID when the Workload API returns identities;
zero, multiple, or unexpected identities are failures.

## Start

From the repository root:

```bash
./scripts/spire-lab-up.sh
./scripts/spire-register.sh
```

Test JWT-SVID issuance:

```bash
./scripts/spire-test-jwt.sh
```

The probe asks for audience:

```text
urn:pingfederate:wai:token-exchange
```

That value is intentionally different from the audience of the PingFederate-issued transaction token.

The probe captures the SPIRE CLI response only in memory, checks the expected
subject and audience, and prints safe metadata. It does not print or persist the
raw JWT-SVID.

## How bootstrap works

1. Start SPIRE Server.
2. Ask SPIRE Server for its trust bundle.
3. Generate a one-time join token bound to the lab agent SPIFFE ID.
4. Start SPIRE Agent using that join token.
5. Register workload entries beneath the attested agent.
6. Run a labeled container that calls the Workload API.
7. SPIRE Agent inspects the caller via the Docker workload attestor.
8. Matching registration entries determine the workload SPIFFE ID.
9. SPIRE returns an SVID.

## Security note

`join_token` is used here only to make the lab easy to bootstrap.

Do not treat this as the default production node-attestation strategy.

The SPIRE Agent needs access to the Docker Engine socket in this lab so the Docker workload attestor can inspect caller containers. Docker socket access is highly privileged. Limit this to the development environment and use deployment-appropriate runtime integration in production.

The Compose lab explicitly runs its SPIRE containers as root and gives the agent
the host PID namespace. This lets a fresh server initialize its Docker-managed
data volume and lets the agent correlate Workload API peer process IDs with the
root-owned Docker socket. These privileges are local-lab accommodations, not a
production deployment recommendation. Production must provision least-privilege
storage ownership and runtime-attestor access appropriate to its platform.

## Windows

The application code remains endpoint-agnostic and should support the SPIRE Agent Workload API on Windows named pipes.

This Docker Compose lab is primarily for Linux containers, including Docker Desktop's Linux VM. Native Windows SPIRE Agent validation remains a separate project task.
