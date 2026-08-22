# MCP Integration

## MVP transport

Use remote MCP over Streamable HTTP.

Keep these concerns separate:

- MCP protocol handling,
- transaction-token verification,
- SPIFFE peer authentication,
- authorization,
- audit.

## Gateway request pipeline

```text
HTTP/mTLS request
  |
  v
SPIFFE peer authentication
  |
  v
Bearer transaction token extraction
  |
  v
PingFederate JWT verification
  |
  v
caller + transaction policy
  |
  v
MCP protocol handler
  |
  v
tool routing policy
  |
  v
SPIFFE mTLS downstream
```

## 2026-07-28 protocol note

The 2026-07-28 MCP specification is stateless at the protocol layer for modern Streamable HTTP requests and adds standard routing headers including method/name information.

Do not hand-roll modern MCP framing. Use a maintained SDK/library and keep authorization middleware outside it.

## Tool authorization

Model authorization input approximately as:

```go
type ToolAuthorizationRequest struct {
    UserID          string
    AgentID         string
    AgentInstanceID string
    TransactionID   string
    Purpose         string
    CallerSPIFFEID  string
    MCPServer       string
    ToolName        string
}
```

The language model must never be the authority that decides whether the call is permitted.

## Propagation

The gateway forwards the same immutable transaction token.

The gateway does not add:

```text
caller=mcp-gateway
```

to the JWT.

The downstream TLS connection already proves the immediate gateway SPIFFE identity.

## Tracing

Keep `TransactionID` and distributed trace IDs separate.

- Transaction ID = security/business delegation correlation.
- Trace ID = observability correlation.

They may be logged together but are not interchangeable.
