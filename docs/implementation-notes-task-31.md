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

## Clean-run result

The first live run correctly rejected the upstream sample certificate, which
was valid only from 14 July 2023 through 13 July 2024. Task 32 replaces those
sample variables with ignored generated bootstrap material before template
expansion.

The completed live run validated the bootstrap leaf, provisioned the OAuth
scope, rotated to the Terraform-managed leaf through a separately validated
TLS phase, created all 21 Terraform resources, rejected a tampered SPIRE actor
token, and verified the issued 20-second transaction JWT. Automatic cleanup
removed the exact random container, volume, certificate, and Terraform state.
