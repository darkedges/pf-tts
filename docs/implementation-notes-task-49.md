# Task 49 implementation notes

Acceptance criteria are recorded in `TASKS.md` and the security-significant
decision is captured in ADR 0011.

The deployment contract creates a separate PingFederate 13.1 logical TTS in
`wai-pingfederate`. The existing PingFederate 12.3 release is an external
system and is excluded from selectors, state, credentials, configuration,
signing ownership, and rollback.

The trusted product boundary consists of the digest-pinned official 13.1 image,
the allowlisted repository-owned profile artifact, read-only Vault bootstrap
inputs, and a distinct persistent `/opt/out`. Public traffic is limited to the
browser-required engine paths on the existing workbench hostname. The admin
API remains private and temporary administrative access must verify exact
version and plugin descriptors before Terraform acts.

Failure gates explicitly reject public admin exposure, mutable images,
embedded secret/bootstrap material, shared-release references, permissive
Vault/SPIRE bindings, and caller-selected AgentID. No validation is relaxed to
make the Kubernetes deployment fit.

Task 49 changes documentation and backlog only. It does not create Vault
records, publish images, configure PingFederate, or apply application resources
to Kubernetes. SPIRE and Vault Secrets Operator were installed separately as
cluster prerequisites before this task and do not authorize later phases.
