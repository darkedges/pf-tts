# Task 52 implementation notes

## Acceptance criteria restatement

Task 52 creates one isolated, durable PingFederate 13.1 StatefulSet with a
dedicated namespace and ServiceAccount, persistent `/opt/out`, private
administrator and engine Services, restrictive security context, bounded
resources and probes, disruption behavior, and default-deny networking. It
starts the digest-pinned derived runtime with its baked, tested plugin, fetches
the public parameterized repository profile, and injects only explicit Task 51
Vault keys. It must report exact version 13.1 and
the reviewed plugin descriptors without selecting shared 12.3 state.

## Security decisions and trust boundaries

The image build boundary accepts exactly a reviewed Dockerfile and tested
plugin JAR. The derived multi-platform image inherits the digest-pinned official
product image and is itself accepted by manifest digest. Configuration is kept
in this repository at `profiles/pingfederate` and fetched through Ping's
supported `SERVER_PROFILE_URL`/`SERVER_PROFILE_PATH` mechanism. It contains
placeholders but no secret or signing values. Kubernetes performs no JAR
download or assembly, so a fetcher cannot substitute the baked plugin in
`/opt/in`.

VSO authenticates with audience `vault` through the exact Task 51 role. Product
pods receive no Kubernetes API token. Bootstrap keys are injected individually
from VSO-created Secrets; a missing key fails Pod creation, and `envFrom` is
forbidden. Runtime CA material is mounted read-only with mode `0400`. Secret
values are absent from Helm values, command arguments, logs, and manifests.

The StatefulSet owns `out-pf13-admin-profile-wai-pingfederate-0` in namespace
`wai-pingfederate`. It does not mount either earlier partial PVC. Both Services are
`ClusterIP`; no Ingress exists. Administrator access remains a bounded local
port-forward. The shared `pingfed` namespace and 12.3 resources are not selected.

The product root filesystem is read-only. PingFederate startup needs mutable
`/opt/staging` and `/etc/motd`, so a non-root init container using the same
digest-pinned image copies only staging into a bounded ephemeral volume and
creates a single bounded `motd` file. These paths are distinct from persistent
`/opt/out`, baked `/opt/in`, and every secret reference.

Failure tests reject mutable images, public Services or Ingress, embedded
Secrets, runtime JAR fetch/assembly, secret-bearing repository profiles, broad
`envFrom` imports, missing exact
bootstrap keys, absent persistence, unsafe probes/security context, Kubernetes
API tokens, TLS bypass, and shared-release references. Validation is not
weakened to accommodate startup.
