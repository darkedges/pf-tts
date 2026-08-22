# Local PingFederate 13.1

The repository provides a development-only PingFederate Admin/Engine container
using the explicit official image tag `pingidentity/pingfederate:2606-13.1.0`.
Do not replace it with `edge`; discovery and Terraform inputs are
version-specific.

## Credentials

Copy `.env.local.example` to `.env.local` and populate:

```text
PING_IDENTITY_DEVOPS_USER=...
PING_IDENTITY_DEVOPS_KEY=...
```

`.env.local` is ignored by Git. Compose requires both values and does not put
them in the committed YAML. `/run/secrets` is an in-memory tmpfs. Do not paste
credentials into command lines, logs, issues, or committed configuration.

## Start

```powershell
Copy-Item .env.local.example .env.local
# Edit .env.local without committing it.
make pf-local-up
make pf-local-logs
```

The ports are loopback-only:

- Admin API/UI: `https://localhost:9999`
- Runtime/token endpoint: `https://localhost:9031`

The official getting-started profile currently documents the lab administrator
as `Administrator` with its published demonstration password. Treat that
password as development-only and never reuse it. Set the discovery environment
in your shell, then run discovery:

```powershell
$env:PF_ADMIN_URL = 'https://localhost:9999'
$env:PF_ADMIN_USERNAME = 'Administrator'
$env:PF_ADMIN_PASSWORD = '<getting-started profile password>'
$env:PF_ADMIN_INSECURE = 'true' # local self-signed certificate only
make pf-discover
make pf-generate-tfvars
```

Confirm `version.json` reports a `13.1` release before reviewing the generated
plugin inputs. The generator independently enforces this check.

## Stop

```powershell
make pf-local-down
```

The named output volume is retained. Removing that volume destroys local
PingFederate state and is intentionally not part of the Make target.
