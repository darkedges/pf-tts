# Implementation Notes: Task 44

## Outcome

Task 44 assembles three separately addressed strict commands without starting
or deploying them. Their SPIFFE identities and listeners are distinct from the
legacy workbench:

- gateway: `spiffe://example.org/gateway/mcp-strict` on 8543;
- MCP server: `spiffe://example.org/mcp/demo-strict` on 8544; and
- API: `spiffe://example.org/api/demo-strict` on 8545.

Every command uses strict middleware, the strict handler constructor for its
role, and exact SPIFFE client/server peers. The gateway accepts only the demo
agent, the MCP server only the strict gateway, and the API only the strict MCP
server.

## Verification trust boundary

The shared strict verifier factory pins RS256, the configured PingFederate
issuer and fixed HTTPS JWKS resolver, Trust Domain `example.org`, scope
`mcp.system.whoami`, and the trusted demo workload-to-agent binding. Missing or
non-HTTPS verifier configuration fails construction.

Each command obtains rotating X.509-SVID material from the configured Workload
API. The exact TLS peer policy and middleware caller allowlist name the same
preceding workload; no trust-domain-wide or permissive authorization is used.

## Failure tests and remaining work

Repository tests prove the distinct identities, strict constructors, exact
peers, listeners, endpoint variables, absence of permissive authorization, and
absence from normal Compose. Factory tests reject missing issuer/JWKS and a
non-HTTPS JWKS URL.

SPIRE does not issue these strict service identities yet and Compose cannot
start the commands. The next task must add an isolated-only profile and exact
SPIRE registrations, followed by an agent that obtains a token through the TTS
adapter. Normal workbench services must remain unchanged.
