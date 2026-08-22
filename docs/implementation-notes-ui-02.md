# Implementation Notes: UI-02

Acceptance criteria: create a dedicated PingFederate browser OAuth/OIDC client
using hosted user authentication, Authorization Code, PKCE, an exact redirect
URI, the `CODE` response type, narrow scopes, a dedicated client secret, and no
refresh or implicit grants. Identity must originate from the reviewed password
credential validator through the hosted IdP adapter, not request attributes.

The browser is outside the OAuth credential boundary. It redirects to
PingFederate's HTML Form IdP Adapter, which is bound to the existing local-lab
password credential validator. PingFederate maps only the adapter's validated
`username` to persistent-grant `USER_NAME`/`USER_KEY`, the user access-token
`user_id`, and the signed OIDC `sub`. No `REQUEST`, `TEXT`, or caller-selected
identity source is used.

The confidential BFF client is distinct from the resource-owner-password,
token-exchange, and MCP resource-server clients. It allows only
`AUTHORIZATION_CODE`, requires PKCE, restricts response type to PingFederate's
exact lowercase `code` API literal, has one
exact HTTPS callback, has no refresh grant, and receives only `openid` and the
transaction invocation scope. It uses the dedicated user reference-token
manager, not the transaction-token manager.

The HTML Form Adapter descriptor and required configuration fields were
captured from the running PingFederate 13.1.0.5 Admin API before Terraform was
written. Raw descriptor reports remain ignored. The installed provider schema
and official provider examples were used for resource shapes.

Failure tests assert mandatory PKCE, exact grants/response type, scope and ATM
restriction, hosted validated identity mapping, absence of request/static
identity sources, a minimum 32-character externally injected secret, rejection
of wildcard/query/fragment redirect URIs, and drift suppression limited to the
provider's two write-only secret representations.

The local apply uses a new CSPRNG-generated `TF_VAR_browser_client_secret` held
only in the ignored environment file. The first apply established the hosted
adapter, mappings, and OIDC policy but PingFederate rejected the uppercase
response-type literal. The restriction was retained and corrected to the
product's exact lowercase `code` literal; the follow-up apply created only the
remaining client. A post-apply plan reports no drift.
