# Argo CD support

`wai-strict-project.yaml` limits the application to namespaced resources in the
`wai-strict` namespace. `wai-strict-application.example.yaml` is a template and must be
reviewed before application: pin `targetRevision` to a commit, create a private
`values-production.yaml` or approved encrypted/external-secret source, and
replace all example image references with immutable digests.

Argo CD must not be given plaintext PingFederate client credentials. The Helm
chart references existing Secret names only. The Application intentionally
does not deploy PingFederate, SPIRE, cluster-wide CRDs, or credentials.

SPIRE identity registration is a separate cluster-administration boundary.
The examples in `spire-identities.yaml` use the exact namespace, component, and
actual Pod ServiceAccount. A mismatched ServiceAccount receives only a rejected
identity that none of the applications accepts. These cluster-scoped resources
are not part of the Argo CD Application's permissions.
