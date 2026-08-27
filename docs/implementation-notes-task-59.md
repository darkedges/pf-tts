# Task 59 implementation notes

## Acceptance criteria restatement

Run PingAuthorize as the strict call chain's decision point in Kubernetes,
selectable per deployment, enforcing the decision the strict rego enforces today.
Keep OPA the default. Deploy in an isolated namespace with a digest-pinned image,
no Ingress, no published LDAP port, and no Kubernetes API token. Supply the
serving certificate from Vault, named for the Service. Verify by decision rather
than by health.

## What made this task different

Every other Ping product in this repository is verified by whether it starts and
answers. PingAuthorize can start, answer, and be wrong — and it did, twice, in
ways that looked like success.

## Three failures found by deploying rather than by reading

**The package is integrity-protected.** Its final element is a
`DataStreamFooter` carrying a SHA-256 digest. Appending rules past it produced
structurally valid JSON that passed every graph check and made the product
crash-loop:

```text
DataStreamVerificationException: Computed digest does not match declared digest
Policy engine cannot be initialized ... server-shutting-down
```

The digest is taken over each element's compact serialisation concatenated
together, with no separators and no enclosing array. That was determined by
reproducing the shipped package's own digest before changing anything, and the
generator now refuses to edit a package whose digest does not already match its
content. Validating this locally, before building anything on top, is what kept
it from becoming a crash-looping pod.

**A ConfigMap cannot deliver the `/opt/in` overlay.** A ConfigMap volume is a
farm of symlinks into a timestamped directory:

```text
/opt/in/..data     -> ..2026_08_27_06_07_06.3187538534
/opt/in/pd.profile -> ..data/pd.profile
```

The product's entrypoint copies `/opt/in` into staging without following them, so
the reviewed dsconfig never staged. The vendor's permissive sample policy stayed
in force and the decision point came up healthy, served the correct certificate,
and permitted every request including the forged ones. The giveaway was
`deploymentPackageId: 83df5673…` — not the reviewed package — and a statement
named "Alway include common attributes" from the vendor sample.

A silent fail-open with every outward sign of success. An init container now
materialises the overlay as real files and fails if the reviewed dsconfig is not
among them.

**The deployed gateway predated the change that reads the provider.** Setting
`AUTHORIZATION_PROVIDER=pingauthorize` altered the Deployment, the pod
environment, and the rendered manifests — and changed nothing, because the
running binary still hardcoded OPA. The end-to-end gate passed: the chain worked,
just through the wrong decision point.

Nothing observable about the pod would have shown this. What exposed it was
counting PingAuthorize's own decision log across an invocation and noticing the
count did not move.

## Verifying by decision

The gate now asks two questions that a healthy pod cannot answer:

- Was the decision point consulted at all? The log count must advance across the
  call chain. If it does not, the gateway is enforcing something else.
- Which package decided? The `deploymentPackageId` must be the reviewed one. Any
  other value means the overlay did not apply and the vendor sample is in force.

Both are skipped when the provider is OPA, where the reviewed rego is mounted
beside the gateway and there is no external decision point to consult.

## Verified in the cluster

With the provider set to `pingauthorize`:

```text
The strict gateway is configured for: pingauthorize
PASS: all 44 Kubernetes end-to-end checks succeeded.
PASS: the decision point was consulted (9 -> 10 decisions).
PASS: decisions come from the reviewed package 1ca3f398-1ba9-4169-a576-7fac52b286db.
```

And back on the default:

```text
The strict gateway is configured for: opa
PASS: the reviewed rego policy is mounted beside the gateway.
PASS: all 44 Kubernetes end-to-end checks succeeded.
```

The switch is a values change in both directions, with no rebuild.

The decision point's own log shows the reviewed tuples deciding correctly:
permits for the strict web-app and demo-agent tuples and the non-strict tuple,
`NOT_APPLICABLE` for a bare purpose, a coarse scope, a mixed agent and workload,
and a forged agent.

## Where the policy is stricter than the rego

The PingAuthorize rules also bind `immediate_caller_id`, which the OPA input does
not even carry. The two providers are therefore not identical: PingAuthorize is
stricter. Dropping the binding to match the rego exactly would have weakened an
existing check, so it was kept and recorded here instead.

## Accepted risks

- The vendor server profile is fetched from a public host at every startup, so
  the namespace needs egress on 443 and the deployment is not air-gapped. That
  profile is also what supplies the permissive fallback, which is why the
  init-container guard exists. Vendoring it is a larger supply-chain decision
  than this task should make.
- The decision call carries no client authentication. The adapter sends no
  credential and its tests forbid one, so trust is one-way TLS plus reachability.
  The NetworkPolicy is the access boundary rather than a defence-in-depth extra.
  Unlike every other hop in the strict chain, this one is not SPIFFE
  authenticated.
- `edge` is a moving product tag. The digest is pinned and the observed version
  recorded, but there is no stable version tag to anchor to.

## Rollback

The provider is a values change:

```text
helm upgrade wai-strict deploy/helm/wai-strict --namespace wai-strict \
  -f deploy/helm/wai-strict/values-kubernetes.yaml
```

That returns the gateway to the reviewed rego. The decision point can then be
removed independently:

```text
helm uninstall wai-pingauthorize --namespace wai-pingauthorize
kubectl -n wai-pingauthorize delete pvc out-wai-pingauthorize-0
kubectl delete namespace wai-pingauthorize
```

Remove the `wai-pingauthorize-11-1` Vault policy and role and the
`wai/pingauthorize-11-1` records only. The PingFederate deployment and the shared
12.3 release are untouched by any of this.
