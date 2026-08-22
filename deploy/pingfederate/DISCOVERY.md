# PingFederate 13.1 Plugin Discovery

PingFederate token processors and Access Token Managers are plugin-backed.
Their Terraform resources require the plugin descriptor ID plus plugin-specific
configuration fields.

Instead of guessing those fields, the project now interrogates the actual
PingFederate Admin API.

## Environment

```bash
export PF_ADMIN_URL='https://localhost:9999/pf-admin-api/v1'
export PF_ADMIN_USERNAME='administrator'
export PF_ADMIN_PASSWORD='...'

# Development with an untrusted local certificate only:
export PF_ADMIN_INSECURE=true
```

`PF_ADMIN_URL` may also be the administrative origin only, such as
`https://localhost:9999`; discovery appends `/pf-admin-api/v1`. URLs containing
embedded credentials, query parameters, or fragments are rejected. The script
prints the effective base URL before making requests.

## Discover

On Windows, the Makefile uses `scripts/run-python.ps1` to locate an installed
Python 3 interpreter or the Codex bundled workspace runtime. On Linux and macOS
it uses `python3`. Override `PYTHON_RUN` if Python is installed elsewhere.

```bash
make pf-discover
```

This fetches:

```text
/version
/idp/tokenProcessors/descriptors
/oauth/accessTokenManagers/descriptors
```

and writes raw payloads plus a recommendation report to
`deploy/pingfederate/discovered/`.

PingFederate requires `X-XSRF-Header: PingFederate` on Admin API requests; the
script includes it.

## Generate the version-specific variable file

```bash
make pf-generate-tfvars
```

This creates:

```text
deploy/pingfederate/terraform/pf13_1.auto.tfvars.json
```

with the discovered plugin IDs.

The file starts with:

```json
{
  "discovery_confirmed": false
}
```

Review the descriptor report and populate the plugin configuration fields
required by your PingFederate instance before changing the gate to `true`.

The generator requires the discovered server version to begin with `13.1`.
It refuses to produce a version-specific tfvars file from an older, newer, or
unknown PingFederate version; plugin descriptor compatibility must not be
assumed across releases.

## Why this exists

The official Terraform provider directly supports PingFederate 13.1 and the
TEPP/ATM/client resources we use. Plugin configuration, however, is described
by the PingFederate plugin descriptors themselves. Discovery makes the lab
repeatable without embedding assumptions from a different PingFederate build.
