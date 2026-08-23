# Implementation Notes: Task 31

Acceptance criteria: recreate PingFederate from the repository-owned profile
and Terraform configuration in isolation, verify a signed token exchange and
the tampered-actor rejection, and clean only exact test-owned resources.

## Trust boundaries

The normal workbench container, volume, ports, and Terraform state are outside
the test boundary. The harness uses a CSPRNG suffix, Docker-assigned loopback
ports, a dedicated volume, and an ignored Terraform working directory. Cleanup
requires exact name patterns and an absolute path beneath the generated test
root.

The fresh runtime certificate is validated by the existing exact-certificate
exporter. Python and Terraform receive that certificate through
`SSL_CERT_FILE`; every insecure-TLS option is explicitly false. Credentials
come from `.env.local`, are passed through process environment, and are never
printed. Isolated Terraform state is sensitive and is erased by default.

The success path applies the required OAuth scope, runs Terraform, obtains a
SPIRE actor JWT-SVID, rejects a tampered actor token, and verifies the resulting
transaction JWT signature and identity bindings. All waits and network calls
are bounded.

## Current clean-run result

The isolation and cleanup controls passed live testing. The test then stopped
at the TLS boundary before Terraform: the current upstream
`getting-started/pingfederate` profile presented a localhost certificate valid
from 14 July 2023 through 13 July 2024. Retrying did not change that result.
The harness did not enable insecure TLS and removed its exact random container,
volume, and state directory.

Completion requires a repository-generated, short-lived bootstrap certificate
installed before the Admin API accepts connections, or an upstream profile
with a currently valid certificate. Its private key must remain generated and
ignored. Using the expired certificate, even when fingerprint-pinned, would
weaken validation and is not an acceptable workaround.
