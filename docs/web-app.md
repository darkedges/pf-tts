# Local web application

The `web-app` command embeds the authenticated interaction and audit interface.
It is configured with environment variables at the process boundary:

| Variable | Purpose |
| --- | --- |
| `WEB_LISTEN` | Browser HTTPS listen address, normally `:8446` |
| `WEB_PUBLIC_URL` | Exact browser origin, normally `https://localhost:8446` |
| `WEB_TLS_CERT_FILE` / `WEB_TLS_KEY_FILE` | Conventionally trusted browser TLS certificate and private-key files |
| `OIDC_AUTHORIZATION_ENDPOINT` | PingFederate authorization endpoint |
| `OIDC_TOKEN_ENDPOINT` | PingFederate browser-code token endpoint |
| `OIDC_REDIRECT_URI` | Exact `https://localhost:8446/oauth/callback` callback |
| `OIDC_CLIENT_ID` | Dedicated `wai-web-app` browser client ID |
| `PF_WEB_CLIENT_SECRET` | Dedicated browser BFF client secret |
| `PF_TOKEN_ENDPOINT` | RFC 8693 exchange endpoint |
| `PF_CLIENT_ID` / `PF_CLIENT_SECRET` | Token-exchange client credentials |
| `PF_TRANSACTION_ISSUER` / `PF_JWKS_URL` | Pinned transaction and ID-token issuer/key configuration |
| `PF_CA_FILE` | PingFederate CA bundle |
| `MCP_GATEWAY_URL` | Fixed HTTPS gateway URL |
| `AUDIT_COLLECTOR_URL` | Fixed HTTPS audit collector URL |
| `SPIFFE_ENDPOINT` | SPIRE Workload API endpoint |

Secrets and TLS private keys must be mounted or injected outside Git. The
browser client secret and token-exchange secret are distinct. The command
fails startup when a required value is absent or a URL violates its HTTPS and
exact-route requirements.
