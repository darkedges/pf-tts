# Implementation Notes: Task 32

Acceptance criteria: generate current local bootstrap TLS and encryption
material outside Git, override the expired upstream sample variables before
first startup, and keep administrator credentials outside the profile.

## Trust boundary

The upstream getting-started bulk template is executable configuration and its
public sample `env_vars` contains a certificate that expired in 2024. The local
overlay replaces that entire variable file with CSPRNG-generated values before
the container starts. The generated file is ignored, mounted read-only, and
reused; recreating it implicitly would rotate keys and break persistent state.

The TLS certificate is a development-only, self-signed leaf bound exactly to
`localhost` and `host.docker.internal`. It is backdated five minutes for clock
settling and valid for seven days by default, with a hard 30-day maximum. The
administrator password is required from `.env.local` through orchestration and
is not written to the profile.

The generated PKCS#12 contains private key material. It and the datastore and
system keys must never be committed, printed, or copied into another profile.
Deleting `deploy/pingfederate/profile/env_vars` intentionally creates new local
bootstrap identity and is appropriate only with a new output volume.

The upstream profile is fetched after `/opt/in` is initially staged. A supported
`02-get-remote-server-profile.sh.post` extension appends the generated local
variables to the container environment after that fetch, restoring local
precedence before template expansion. It rejects missing, symlinked, or CRLF
input and never echoes values.

Terraform rotates from the short-lived bootstrap leaf to the managed local
runtime leaf in an explicit first phase. PingFederate can issue that leaf with a
`NotBefore` a few seconds ahead of the caller. The harness retains strict
validation, waits at most 90 seconds for validity, refreshes the exact pinned
leaf, and only then applies resources that require additional Admin API calls.
