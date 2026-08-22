# Threat Model

## Assets and trust boundaries

Protected assets are user authority, logical AgentID bindings, SPIFFE private
keys, PingFederate signing keys, transaction JWTs, OAuth credentials, tool
routes, and audit integrity. The main boundaries are: untrusted request input
to PingFederate; Workload API caller to SPIRE attestation; network peer to
SPIFFE mTLS; transaction bearer token to local JWT verification; and MCP tool
input to fixed target routing.

Authorization requires a verified immutable transaction context, an
independently authenticated immediate SPIFFE caller, and target policy.

## Threat scenarios

### Compromised AI agent

It can use tokens and SVIDs available to its own process, but cannot select a
different SPIFFE ID or logical AgentID. Exact workload binding, short TTL,
scope/audience restrictions, and downstream caller policy limit reach. It must
not call the protected API directly.

### Compromised MCP gateway

It can invoke configured downstream routes during valid transactions. It
cannot alter signed transaction claims or authenticate as the MCP server.
Downstream services verify both the original token and the gateway's SPIFFE ID.

### Compromised MCP server

It can access tools/data allowed to its SPIFFE ID, but cannot rewrite the
transaction or authenticate as another server. The API accepts only the exact
MCP-server caller and independently validates the token.

### Compromised downstream API

It can disclose data it owns but receives neither the original user token nor
SPIFFE private keys of callers. Minimized claims and target-specific mTLS reduce
the blast radius.

### Stolen subject token

The token alone is insufficient: exchange also requires the actor JWT-SVID and
confidential client authentication. Never propagate the subject token after
exchange.

### Stolen JWT-SVID

Audience, trust domain, signature, lifetime, and exact workload binding are
checked. The token is useful only with the authenticated exchange client and a
valid subject token. Maximum accepted lifetime is bounded.

### Stolen transaction token and replay

The MVP token is bearer material. Short exact TTL, narrow audience/scope,
SPIFFE mTLS caller policy, TLS, and `jti` audit correlation reduce replay but do
not eliminate it. A replay cache or proof of possession is post-MVP and must
not be claimed here.

### SPIRE compromise

A compromised SPIRE control plane can mint workload identities and defeats the
runtime-identity boundary. Protect SPIRE keys and registration authority,
replace join-token bootstrap in production, and alert on registration changes.

### PingFederate compromise

A compromised issuer can mint arbitrary transaction context. Protect Admin
API access and signing keys, constrain plugins and mappings, rotate keys, and
make downstream issuer/JWKS allowlists explicit.

### Signing-key compromise

An attacker can forge tokens until the key is removed and consumers refresh
JWKS. Use PingFederate-managed private keys, stable `kid`, rotation, short token
TTL, and an explicit `RS256` allowlist.

### Confused deputy

A valid agent might request an unintended target. Fixed gateway routes,
unambiguous tool ownership, transaction audience, restricted scope, and exact
downstream caller policy deny ambient authority.

### SSRF and routing abuse

Targets are trusted HTTPS configuration, never request URLs. Unknown and
ambiguous tools fail. Redirect behavior must not broaden allowed hosts; future
multi-target clients should reject cross-host redirects explicitly.

### Malicious tool input

Tool schemas validate structure, services enforce authorization independently,
and sensitive arguments are excluded from audit. Inputs remain untrusted at
every downstream parser and must not become URLs, queries, or commands without
context-specific validation.

## Required failure posture

Reject unknown issuers or keys, wrong algorithms/audiences, expired or future
tokens, missing required claims, ambiguous identities, unknown bindings,
unapproved purposes or tools, incorrect mTLS callers, and missing credentials.
Errors and logs never include bearer or signing material.
