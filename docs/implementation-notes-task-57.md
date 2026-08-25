# Task 57 implementation notes

## Acceptance criteria restatement

Prove and hand over the complete isolated Kubernetes Transaction Token solution
with repeatable rollback. Pass browser login, strict exchange, immutable-token
call chain, and correlated audit evidence through API completion. Fail forged
logical AgentID, wrong SPIFFE workload or caller, wrong audience, expired token,
unapproved target or tool, legacy Bearer transport, and a stolen token presented
over the wrong mTLS identity. Scan logs and rendered or live resources for raw
tokens, credentials, private keys, unsafe public Services, and unexpected
identity entries. Record pinned versions and digests, sanitized evidence,
backup and restore steps, readiness observations, and exact rollback commands.
Rollback must remove only the isolated WAI releases and must not mutate or
interrupt the existing PingFederate 12.3 deployment.

## The gate

`make pf13-k8s-verify` runs `scripts/verify-pf13-kubernetes-end-to-end.ps1`,
which checks workload readiness, delegates to the Task 56 public-surface gate,
runs `deploy/pingfederate/scripts/verify_kubernetes_end_to_end.py`, and then
scans live logs and rendered resources for disclosure.

The Python gate drives the real browser path through the single reviewed public
hostname and asserts 31 checks. It reads the lab credential from environment
that the wrapper populates from the Vault-synchronized Secret, and prints no
credential, code, or token. Sanitized evidence is written to
`deploy/pingfederate/generated/pf13-kubernetes-end-to-end-evidence.json`.

## Defects this gate found

The gate was not a formality. Building it and running it end to end exposed two
defects that every existing test had missed, both of which made the deployed
strict call chain non-functional.

**The strict hops did not share one binding set.** When the workbench was added
to the strict path, `cmd/strict-mcp-gateway` received the
`urn:agent:web-app` binding, but `cmd/strict-demo-mcp-server` and
`cmd/strict-demo-api` still called `demoenv.StrictTxnVerifier()`, whose map
contained only `urn:agent:demo`. A fully valid workbench transaction was
verified at the gateway, authorized by policy, and then rejected one hop later.
The rejection happened inside the middleware before any audit event could be
written, so the failure was invisible in the audit trail: the operator saw an
allowed decision at the gateway and a 502 at the browser with nothing between.

Every strict hop now verifies against `demoenv.StrictWorkloadAgentBindings`.
The entries remain exact, so a workload still cannot assert a different AgentID;
they simply cannot drift apart per binary any more.
`TestStrictHopsShareOneReviewedWorkloadAgentBindingSet` fails if a command
reintroduces its own inline map.

**The strict authorization policy could never allow anything.** The policy
required `input.purpose == "system.whoami"`, but `StrictTxnMiddleware` derives
the purpose from the signed route carried inside the transaction token, as
`"<target>:<tool>"`. Every strict call was therefore denied with
`policy_denied`.

The middleware is right and the policy was wrong: the route comes from
`claims.TransactionContext.WAI.Target` and `.Tool`, so the purpose is composed
entirely from signed material and cannot be forged by a caller. The policy now
expects `demo:system.whoami`.

The unit test hid this. It built the identity context by hand with a bare tool
name rather than through the middleware, so it exercised a tuple the deployed
gateway never produces. It now builds the tuple the gateway actually evaluates
and includes a negative case rejecting a bare tool name.

## Positive evidence

One browser login through Cloudflare, PingFederate's hosted form, scope consent,
the exact callback, the strict exchange, and the strict chain through the
protected API. The recorded trail for a single interaction:

```text
transaction.exchange.succeeded   allow  strict_transaction_token_verified
transaction.verify.succeeded     allow  strict_txn_token_verified
mcp.tool.allowed                 allow  policy_allowed
transaction.verify.succeeded     allow  strict_txn_token_verified
transaction.verify.succeeded     allow  strict_txn_token_verified
```

All five events carry one `transaction_id` and one identical token fingerprint,
which is the immutability proof required by ADR 0001: no hop rewrote, reissued,
or extended the inner token. `immediate_caller_spiffe_id` changes across the
chain (workbench, then gateway, then MCP server), which is the ADR 0002 proof
that immediate caller identity comes from the authenticated SPIFFE mTLS peer
rather than from the token. Evidence records the token by SHA-256 fingerprint,
issuer, audience, scope, JWT ID, and validity window only.

## Negative evidence

Proven live from the position of an ordinary external user:

| Case | Result |
| --- | --- |
| Unapproved tool | HTTP 400 |
| Unapproved purpose | HTTP 400 |
| Wrong CSRF token | HTTP 401 |
| Cross-origin submission | HTTP 401 |
| Unauthenticated session | HTTP 401 |
| Forged redirect URI | HTTP 400 on PingFederate's own error page |
| Unapproved scope | `error=invalid_scope` to the exact registered callback |
| `/pf-admin-api/v1/version`, `/pf-admin/`, `/internal/*` | HTTP 404 |
| Unapproved `Host` header on an engine path | rejected |

Two of these initially reported as failures and were traced to the gate, not the
deployment. A rejected scope is an OAuth error delivered by redirect, so
asserting a 4xx status was wrong; the gate now asserts the error code and that
it went to the exact registered callback. An unauthenticated request sent
without a User-Agent was answered 403 by the edge before the workbench saw it,
which masked the application's own 401; the gate now sets an explicit agent.

A third reported failure was also a gate defect: the `ExternalName` Service that
aliases the isolated engine was counted as public exposure. `ExternalName`
allocates no address and publishes nothing, so the gate now flags only
`LoadBalancer` and `NodePort`, and separately asserts that the alias resolves to
exactly `wai-pingfederate-engine.wai-pingfederate.svc.cluster.local`.

## Superseded by the origin split

The evidence above was recorded while the authorization server shared the
application's hostname and while backchannel calls travelled out through the
edge. Both were changed by [Task 58](implementation-notes-task-58.md), so read
these two together: the gate now runs against two origins and asserts that the
engine no longer answers on the application hostname, and the issuer recorded in
transaction evidence is `https://tst.ping.darkedges.com`. The positive and
negative results themselves are unchanged, and the check count grew from 31 to
38.

## Coverage boundary

Four required negative cases cannot be produced from a browser, because they
require a caller that already holds a SPIFFE identity inside the mesh: a forged
logical AgentID, a wrong SPIFFE workload, legacy Bearer transport to a strict
hop, and a stolen token replayed over a different mTLS identity.

These are proven by the Go suite, which constructs those callers directly:
`pkg/authorization/strict_policy_test.go` rejects substituted logical/runtime
identity pairs and scope expansion, `pkg/middleware` covers caller binding and
legacy Bearer rejection, and `pkg/transaction` covers audience, expiry, and
issuer validation. The live gate deliberately does not attempt to mint an
unauthorized SPIFFE identity, because doing so would require registering one,
which is itself the condition the deployment forbids.

## Disclosure scan

- No compact JWS appears in the last 500 log lines of any strict workload.
- No `client_secret`, `client-secret`, or `PRIVATE KEY` marker appears in those
  logs.
- The rendered `wai-strict` release contains no `Secret`, no `stringData`, no
  token, and no key material.
- No WAI Service is a `LoadBalancer` or `NodePort`.
- The isolated PingFederate namespace publishes no `Ingress`; the administrator
  Service and port 9999 remain reachable only through a bounded port-forward.

## Pinned versions and digests

Product runtime is PingFederate `13.1.0.5`, attested over the private channel
before every configuration run. Image digests are recorded in
`deploy/images/strict-36d0eb0c2f1b.json` and pinned in
`deploy/helm/wai-strict/values-kubernetes.yaml`. The publication-lock test now
resolves the record from the revision the reviewed values declare, so a
republish cannot leave the values pinned to one record while the test validates
another.

## Readiness observations

Two behaviours are worth knowing before re-running the gate.

A strict workload started before SPIRE has issued its identity exits with
`fetch X.509-SVIDs: rpc error: code = PermissionDenied desc = no identity
issued` and restarts once. This is expected on a fresh rollout and resolves
without intervention, but it means the first request after `helm upgrade` can
fail while a pod is still on its first attempt.

The SPIRE agent caches JWT-SVIDs by SPIFFE ID and audience, not by pod. After
changing a registration's `jwtTtl`, a restarted workload still receives the
previously cached token until it expires. Clearing that cache requires
restarting the `spire-agent` DaemonSet.

## Rollback

Rollback operates only on the isolated releases and namespace-scoped resources.
The shared PingFederate 12.3 release in namespace `pingfed` is neither a source
nor a target, and none of these commands select it.

Back up the persistent signing state before any destructive step:

```text
kubectl -n wai-pingfederate exec wai-pingfederate-0 -- tar czf - /opt/out/instance/server/default/data > pf13-out-backup.tgz
cp deploy/pingfederate/generated/pf13-kubernetes.tfstate pf13-kubernetes.tfstate.backup
```

Roll the application back one revision, or remove it entirely:

```text
helm rollback wai-strict --namespace wai-strict
helm uninstall wai-strict --namespace wai-strict
```

Remove the isolated logical TTS. The persistent volume claim is deliberately not
deleted by `helm uninstall`, so removing it is an explicit second step:

```text
helm uninstall wai-pingfederate --namespace wai-pingfederate
kubectl -n wai-pingfederate delete pvc out-pf13-two-phase-wai-pingfederate-0
```

Remove the dedicated cluster identity entries and the namespaces:

```text
kubectl delete -f deploy/argocd/spire-identities.yaml
kubectl delete namespace wai-strict wai-pingfederate
```

The dedicated Vault policy and role are named `wai-pingfederate-13-1` and
`wai-strict`; remove them and the `wai/pingfederate-13-1` and `wai/workbench`
KV records only. Confirm the shared release is untouched afterwards:

```text
helm list --namespace pingfed
kubectl -n pingfed get pods
```
