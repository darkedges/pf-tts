# Implementation Notes: Task 29

Acceptance criteria: export the local PingFederate bulk configuration over an
authenticated, certificate-validated, bounded connection; parameterize it with
an immutable and isolated converter; keep every generated artifact ignored;
and require review before it can enter the trusted startup profile.

## Trust boundaries

The Admin API is privileged and its response can contain credentials, encrypted
secrets, certificates, keys, and deployment-specific identifiers. The wrapper
therefore accepts only `https://localhost:9999/`, authenticates from the ignored
`.env.local`, pins the exact current local runtime certificate, bounds time and
bytes, and never includes an error response body in an exception.

The converter image is third-party executable code. It is selected by immutable
digest and runs without networking, capabilities, privilege escalation, or a
writable root filesystem. Its reviewed parameterization configuration is the
only read-only input outside the ignored generated workspace.

The converter's `env_vars` file contains extracted values, not merely variable
names. The raw export, converter log, environment properties, and substituted
JSON all remain under `deploy/pingfederate/generated/bulk-export`. The workflow
does not copy them into `deploy/pingfederate/profile`; doing so would cross from
unreviewed generated state into trusted executable configuration.

## Operation

First refresh the exact local runtime certificate, then export:

```powershell
make pf-export-ca
make pf-profile-export
```

The committed `pf-config.json` externalizes encrypted credential fields. Before
conversion, the wrapper creates an application-only document from exact
resource and object-ID allowlists. After conversion it rejects residual
encrypted fields, literal password or secret fields, and private-key PEM data.
Review the generated substituted JSON and variable names locally; never commit
the extracted values.
