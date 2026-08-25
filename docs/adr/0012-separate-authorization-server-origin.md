# ADR 0012: Separate authorization server origin and in-cluster backchannel

## Status

Accepted. Supersedes the single-hostname decision in
[ADR 0011](0011-isolated-kubernetes-pingfederate-13-1.md), which said
`workbench.ping.darkedges.com` was the only new public hostname and explicitly
rejected exposing a separate engine hostname. Every other part of ADR 0011
stands: the isolation of the 13.1 release, the private administrator API, the
digest-pinned runtime, and PingFederate as the only signer.

## Context

ADR 0011 minimised the public surface by putting the authorization server's
browser-required engine paths on the same hostname as the application, routed by
an explicit `/as/`, `/pf/`, `/idp/` path allowlist. Narrowing the number of
public hostnames was the stated reason.

Running the deployment revealed that the shared hostname was not neutral. It
made the authorization server and the application **same-origin to the browser**:

```text
PingFederate  Set-Cookie: PF=…;      Path=/; Secure; HttpOnly; SameSite=None
workbench     Set-Cookie: <session>; Path=/; Secure; HttpOnly; SameSite=Lax
```

Both are `Path=/`, and a cookie path is not a security boundary. PingFederate's
session cookie was therefore attached to every workbench API call, and the
workbench's session identifier was sent to the authorization endpoint on every
authorization request. One hostname also means one CSP origin, one
`form-action 'self'` scope, and one set of same-origin guarantees shared between
a relying party and the authority that authenticates for it.

Separately, ADR 0011 required that "the adapter and workloads use the internal
engine Service". They did not. Every request reaching PingFederate arrived from
the ingress controller, including the RFC 8693 exchange, because:

- the engine certificate was the Docker-era bootstrap leaf, `CN=localhost` with
  SANs for `localhost` and `host.docker.internal` only, so nothing could
  validate the engine by its in-cluster name and nginx had to be pinned to
  `proxy-ssl-name: localhost`;
- `PFHTTPClient` appended `PF_CA_FILE` to the system certificate pool instead of
  pinning it, so any public certificate authority satisfied the client;
- the strict egress policy allowed TCP 443 to any destination.

Together these meant the token exchange, carrying the user's access token as
`subject_token` and the agent's JWT-SVID as `actor_token`, resolved a public
address, left the cluster, and returned through the edge. Whatever terminated
that TLS could read both tokens.

## Decision

Give the authorization server its own origin, `tst.ping.darkedges.com`, and keep
every in-cluster caller off the public path entirely.

Browser traffic reaches the authorization server only at
`tst.ping.darkedges.com`, restricted to the same reviewed `/as/`, `/pf/`,
`/idp/` prefix allowlist. Those prefixes are removed from
`workbench.ping.darkedges.com`, which serves only the application. The
administrator API, the administrator console, and port 9999 remain unpublished
on both hostnames.

The redirect URI stays on the application origin,
`https://workbench.ping.darkedges.com/oauth/callback`. It identifies the client,
not the authorization server.

PingFederate's runtime base URL becomes `https://tst.ping.darkedges.com`, which
makes it the issuer of every token this logical TTS signs. Consumers allowlist
exactly that value.

The engine serves a certificate that names it as it is actually addressed: the
public authorization server hostname, and the in-cluster Service in each form
Kubernetes resolves. Generation and activation are separate steps, because the
certificate cannot be swapped until every client already trusts the new leaf.
The administrator console keeps the bootstrap `localhost` key, since it is
reached only through a bounded loopback port-forward.

Backchannel calls -- the token exchange, the authorization code exchange, and
JWKS retrieval -- address the engine Service directly. `PF_CA_FILE`, when
configured, becomes the only trust anchor, so pointing a workload at a public
address is a connection failure rather than a silent disclosure. The blanket
TCP 443 egress is replaced by an explicit rule to the engine, and the isolated
namespace admits 9031 from exactly the strict workloads and the ingress
controller.

## Trust boundaries

- The application origin and the authorization server origin are distinct sites
  to the browser. Neither one's cookies reach the other.
- The issuer is a token identifier, not a location to fetch from. It stays the
  public authorization server origin even though JWKS is retrieved internally.
- nginx and Cloudflare remain routing and TLS boundaries only, and now carry no
  backchannel traffic at all. No forwarded header asserts user, agent, or
  workload identity.
- The administrator API remains reachable only from inside the isolated
  namespace, in practice only through a bounded port-forward.

## Consequences

The public surface grows by one hostname. That is the cost being accepted, and
it is bounded: the same three path prefixes, no admin paths, and no new
internal service published.

The issuer changes, so every consumer re-pins. This is a deliberate one-time
cost that also removes an existing collision, since the isolated deployment
previously issued tokens under the same issuer string as the Docker harness.

Cutover requires the new hostname to resolve before PingFederate's base URL
changes. Otherwise the hosted login page renders a `<base href>` the browser
cannot reach, and the authorization endpoint is unreachable.

## Rejected alternatives

- Keep one hostname and rely on path separation: a cookie `Path` is not a
  security boundary, and the browser's same-origin model does not read the
  ingress path allowlist.
- Keep the public backchannel and pin `ServerName` to `localhost` the way nginx
  does: this severs the certificate from the endpoint's real identity, which is
  the binding the rest of the design depends on.
- Publish the whole engine surface on the new hostname: the prefix allowlist is
  a control worth keeping, and a dedicated hostname is not a reason to drop it.
- Give the administrator API a hostname of its own: nothing requires browser
  access to it, and a port-forward is already sufficient.
