# Task 58 implementation notes

## Acceptance criteria restatement

Give the authorization server its own origin so it is no longer same-origin with
the application it authenticates for, and stop backchannel traffic from leaving
the cluster. Record the decision in ADR 0012 and mark what it supersedes rather
than rewriting it. Keep the reviewed path allowlist, keep the redirect URI on the
application origin, make the issuer the authorization server's own origin, serve
an engine certificate that names the engine as it is actually addressed, and
treat `PF_CA_FILE` as the only trust anchor.

## Why the shared hostname was not neutral

ADR 0011 put the engine's browser paths on the application hostname to minimise
the number of public hostnames. Running the deployment showed what that cost.

```text
PingFederate  Set-Cookie: PF=…;      Path=/; Secure; HttpOnly; SameSite=None
workbench     Set-Cookie: <session>; Path=/; Secure; HttpOnly; SameSite=Lax
```

Both are `Path=/` on one origin. PingFederate's session cookie was therefore
attached to every workbench API call, and the workbench's session identifier was
sent to the authorization endpoint on every authorization request. A cookie path
is not a security boundary, and the browser's same-origin model does not read the
ingress path allowlist. One hostname also means one CSP origin and one
`form-action 'self'` scope shared between a relying party and the authority that
authenticates for it.

## The larger finding

Investigating the hostname surfaced something worse. Every request reaching
PingFederate arrived from the ingress controller, including the RFC 8693
exchange:

```text
adapter → public DNS → Cloudflare edge → tunnel → nginx → PingFederate
```

That request carries the user's access token as `subject_token` and the agent's
JWT-SVID as `actor_token`. Whatever terminated that TLS could read both. ADR 0011
had required that "the adapter and workloads use the internal engine Service";
they did not, and nothing detected it.

Three things allowed it:

- The engine certificate was the Docker-era bootstrap leaf, `CN=localhost` with
  SANs for `localhost` and `host.docker.internal` only. Nothing could validate
  the engine by its in-cluster name, so nginx was pinned to
  `proxy-ssl-name: localhost` and workloads used the public URL instead.
- `PFHTTPClient` appended `PF_CA_FILE` to the system certificate pool rather than
  pinning it. Any public certificate authority satisfied the client, so the CA
  pin bought nothing on that path.
- The strict egress policy allowed TCP 443 to any destination, which is what made
  the public route reachable from inside the cluster at all.

## Implementation

**Certificate.** `runtime_tls.tf` generates a runtime key naming the engine as it
is actually addressed: `tst.ping.darkedges.com` and the in-cluster Service in
each resolvable form, with `localhost` retained for the transition. Generation
and activation are separate variables, because the engine's TLS identity cannot
be swapped until every client already trusts the new leaf. The administrator
console keeps the bootstrap key: it is reached only through a bounded loopback
port-forward, so `localhost` is the correct identity for it, and rotating it
would break the channel Terraform is connected over.

The reviewed sequence, executed in this order:

1. Generate the key, activation still off.
2. Export the leaf and publish a Vault trust bundle carrying both it and the
   bootstrap leaf.
3. Restart every client so it loads the two-anchor bundle.
4. Activate, so the engine begins serving the new leaf with no trust gap.
5. Once verified, prune the bootstrap leaf so exactly one anchor remains.

Step 5 matters. A transitional bundle that is never pruned leaves a trust anchor
nothing needs, which is the same class of problem as the shared origin: not
exploited, but not justified either.

**Trust.** `PFHTTPClient` now treats a configured `PF_CA_FILE` as the only
anchor. Pointing a workload at a public address is a connection failure instead
of a silent disclosure. The system pool is used only when no `PF_CA_FILE` is
configured, which is the case for a deployment fronted by a publicly trusted
certificate.

**Routing.** The engine's browser paths move to `tst.ping.darkedges.com` with the
same `/as/`, `/pf/`, `/idp/` allowlist, and are removed from the application
hostname. The gate asserts both halves: that the authorization request leaves the
application origin, and that engine paths no longer answer on it. Verifying only
the first would pass while both hostnames still served the engine, which is the
state the split exists to end.

**Network.** The blanket TCP 443 egress is replaced by an explicit rule to the
engine, and the isolated namespace admits 9031 from exactly the strict workloads
and the ingress controller. Port 9999 stays namespace-local. This cluster has no
NetworkPolicy controller, so these are declarative here; SPIFFE mTLS and strict
token verification remain the enforced boundaries.

## Verification

The intended split is visible in PingFederate's own request log:

```text
POST /as/token.oauth2          10.1.205.173  workbench
POST /as/token.oauth2          10.1.205.168  adapter
GET  /as/authorization.oauth2  10.1.172.225  ingress-nginx
```

Backchannel calls come from the workloads directly; only browser traffic arrives
through the edge. Before the change, both came from `10.1.172.225`.

Cookie isolation is confirmed at the two origins: the `PF` cookie is set on
`tst.ping.darkedges.com`, the application session on
`workbench.ping.darkedges.com`, and `/pf/JWKS` answers 200 on the authorization
server and 404 on the application.

All 38 checks in `make pf13-k8s-verify` pass, including on a single trust anchor
after the bootstrap leaf was pruned.

## Gate defects found while doing this

Two checks reported the deployment as broken when the deployment was correct.

The hosted login page is rendered by PingFederate, so its `<base href>` is the
authorization server's origin. The check still compared it against the
application origin and reported the correct value as a failure.

Form posts carried a hard-coded application origin. A browser sends the origin of
the page hosting the form, so the credential and consent posts to PingFederate
were sending an origin no real browser would send. The origin is now derived from
the target, which leaves the cross-origin negative case meaningful because it
still overrides it explicitly.

## Cutover ordering

PingFederate's base URL is the origin its hosted pages render against, so it must
not change before the new hostname resolves. Changing it first produces a login
page whose `<base href>` and root-relative form action point somewhere the
browser cannot reach: the page renders and cannot be submitted, which is exactly
the failure mode recorded in [Task 53](implementation-notes-task-53.md).

The tunnel is remotely managed, so the public hostname mapping is an operator
action in the Cloudflare dashboard, not a repository change.

## Rollback

The trust bundle is versioned in Vault, so the transitional two-anchor bundle can
be restored:

```text
vault kv rollback -mount=kv -version=5 wai/pingfederate-13-1/runtime-ca
```

Reverting the origin split means setting `pf_base_url` back to the application
origin, restoring `ingress.pingFederateHost`, and re-pinning
`global.pingFederate.issuer`. Reverting reintroduces the shared-origin cookie
exposure, so it is a deliberate step, not a routine one.
