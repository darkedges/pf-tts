# PingFederate local server profile

This profile is mounted read-only at `/opt/in` and layered with Ping's pinned
`getting-started/pingfederate` profile. It contains only repository-owned,
public startup artifacts.

`make pf-profile` builds and tests the custom token processor/access-token
manager plugin, then places the generated JAR under
`instance/server/default/deploy/`. The generated JAR is deliberately ignored;
source and tests remain authoritative.

Credentials, licenses, private keys, SPIRE bundles, Terraform inputs, and
Terraform state must never be added to this profile.

`make pf-profile-artifact` builds a scratch OCI artifact from a fresh temporary
context containing only the reviewed plugin JAR and public profile hook, then
enumerates the exported root filesystem. `make pf-profile-artifact-push`
publishes the same artifact for amd64/arm64 only from a clean Git revision.
The PingFederate product image and extracted SDK libraries are never included.
