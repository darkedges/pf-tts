# Implementation Notes: Task 27

## Acceptance criteria

PingFederate and PingAuthorize start from digest-pinned vendor images with
repository-owned profile overlays mounted read-only at `/opt/in`.
PingFederate's startup target builds and tests the custom plugin first;
PingAuthorize's first setup selects the committed deployment package through
dsconfig. Neither profile contains secrets or generated trust material.

## Trust boundaries

The profile overlay is trusted executable configuration. It may add the
reviewed custom plugin or select the reviewed deployment package, but it cannot
provide credentials, licenses, private keys, Terraform state, or generated
SPIRE/Ping certificates. Those remain ignored and externally injected.

The PingFederate plugin JAR is generated from committed source only after its
Maven tests pass. The builder uses fixed source and destination paths, requires
the reviewed 13.1 SDK dependencies, rejects a missing or unexpectedly small
artifact, and reports only its public SHA-256 digest. Maven uses a fixed output
timestamp and a pinned JAR plugin so identical source produces an identical
profile artifact.

PingFederate startup and configuration remain separate trust operations. The
profile starts the pinned product and installs the plugin. A clean instance
then requires the explicit `pf-ensure-scope` and `pf-apply` steps. This avoids
silently mutating OAuth clients, client secrets, signing keys, or TLS settings
as a side effect of starting a container.

PingAuthorize reads the policy from a separate read-only mount. Its dsconfig
uses the embedded PDP, trust-framework v2, a static local file, and the exact
WAI package path. It cannot fall back to the vendor sample policy or load a
policy over the network.

The stable `pingauthorize-wai` hostname is both its Docker DNS identity and the
required certificate SAN. The container joins only `docker_wai-app`; the
network bootstrap rejects an existing network using any driver other than the
expected local bridge driver.

## Failure coverage

Static orchestration tests reject unpinned images, embedded DevOps
credentials, writable profile/policy mounts, sample or network-loaded policy
fallback, missing plugin build/test steps, unbounded artifact paths, and an
unexpected application-network driver.
