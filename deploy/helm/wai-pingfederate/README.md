# Isolated PingFederate 13.1

This chart owns only the WAI logical TTS in namespace `wai-pingfederate`. It
does not select, reference, upgrade, or modify the shared PingFederate 12.3
release in namespace `pingfed`.

The derived PingFederate runtime is pinned by immutable manifest digest. It
inherits the digest-pinned official 13.1 product and embeds only the tested
custom plugin JAR at `/opt/in`. PingFederate fetches the parameterized public
profile from `https://github.com/darkedges/pf-tts.git` at
`profiles/pingfederate`. Vault Secrets Operator synchronizes isolated records;
Kubernetes injects their individual keys without rendering values into Helm
manifests or the repository profile. The product owns a distinct `/opt/out`.

The administrator and engine Services are private `ClusterIP` Services. There
is no Ingress. Task 53 reaches port 9999 only through a bounded port-forward.
Task 56 may route explicitly allowlisted engine paths through the existing
workbench hostname; it must not expose the administrator Service.

Prerequisites are Kubernetes 1.33 or newer, Vault Secrets Operator, the Task 51
policy/role/records, and the `hostpath` storage class for
this local cluster. A separately bootstrapped Secret named
`wai-vault-server-ca` must contain only the verified public Vault CA as
`ca.crt`; the chart never copies or renders the Vault TLS private key. Render
and validate before installation:

```text
helm lint deploy/helm/wai-pingfederate
helm template wai-pingfederate deploy/helm/wai-pingfederate --namespace wai-pingfederate --validate
```

Install only after reviewing the digests and rendered resources:

```text
kubectl create namespace wai-pingfederate
helm upgrade --install wai-pingfederate deploy/helm/wai-pingfederate --namespace wai-pingfederate
```
