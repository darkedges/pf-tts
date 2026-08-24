# Implementation Notes: Task 46

## Acceptance criteria

Task 46 must exercise one PingFederate-signed Transaction Token unchanged over
agent, gateway, MCP server, and API hops, with exact SPIFFE mTLS at every hop.
It must also prove that the strict gateway rejects legacy Bearer transport and
a caller with the wrong SPIFFE identity. The run must be isolated, bounded,
token-free in captured output, and remove only its randomly named resources.

## Trust boundaries and failure checks

The agent-to-gateway HTTP boundary accepts only one `Txn-Token` field after the
TLS client has authenticated as the exact approved agent SPIFFE ID. A dedicated
failure probe presents an invalid legacy Bearer field from that otherwise-valid
workload and requires HTTP 401. This verifies that transport validation is not
bypassed by a trusted TLS caller.

The gateway TLS boundary independently authorizes the immediate caller. A
second failure probe uses the strict MCP server's valid, cryptographically
issued X.509-SVID and requires the TLS exchange to fail before the HTTP handler
is reached. The test does not weaken identity validation or substitute a
caller-asserted identity.

All probe responses and collected logs are bounded and scanned for compact JWT
shapes, known credentials, Authorization fields, and client secrets. Errors and
success output contain only status and correlation-safe statements.

## Live evidence

On 2026-08-24, `make pf-test-strict-call-chain` passed against fresh isolated
PingFederate container `wai-pf-clean-41ab0b43ac846efd`. The gate verified the
20-second strict inner Transaction Token, completed agent → adapter → gateway →
MCP server → API with unchanged transaction correlation, rejected legacy
Bearer transport, rejected the strict MCP workload at the gateway mTLS
boundary, and found no credential-shaped material in bounded captured output.

The harness then removed the exact random PingFederate, adapter, probe, gateway,
MCP, and API containers and images, its bridge network, output volume,
certificate, Terraform work directory, and isolated state. It never addresses
normal workbench resources by name or Compose project.
