# PingFederate Terraform

This directory is the authoritative PingFederate configuration layer for the WAI lab.

## Provider

The project pins the official provider family:

```hcl
source  = "pingidentity/pingfederate"
version = "~> 1.9"
```

Provider 1.9.x supports PingFederate 12.2 through 13.1.

## What Terraform manages now

The baseline declares:

- user/subject IdP token processor,
- SPIRE JWT-SVID actor IdP token processor,
- OAuth Token Exchange Processor Policy,
- actor-token-required policy behavior,
- transaction JWT Access Token Manager,
- access-token mapping,
- confidential OAuth token-exchange client,
- restricted token-exchange scope,
- explicit SPIFFE-to-logical-agent bindings as Terraform input.

## Deliberate staged implementation

The first Terraform baseline only maps cryptographically established fields:

```text
subject TOKEN_SUBJECT -> user_id
actor TOKEN_SUBJECT   -> workload_id
```

It intentionally leaves these unmapped until a trusted server-side source is added:

```text
agent_id
agent_instance_id
transaction_id
transaction_purpose
```

This prevents Terraform from institutionalizing a design where a caller can simply assert its desired AgentID.

The custom transaction ATM performs trusted server-side AgentID binding and
transaction metadata generation. See `docs/pingfederate.md`. The TEPP leaves
those caller-controlled fields unmapped; do not weaken this boundary.

## Why some plugin fields are variables

PingFederate plugin instances expose configuration fields defined by their plugin descriptors. Those field names/IDs can vary with the selected plugin and product release.

Rather than put guessed field names into a supposedly reproducible project, this baseline makes the plugin descriptor IDs and configuration fields explicit inputs.

The next lab step is to query the target PingFederate 13.1 Admin API for:

1. OAuth Token Processor descriptor,
2. JWT Token Processor 2.0 descriptor,
3. JWT Bearer Access Token Manager descriptor.

Once those exact descriptors are known, pin the values in a lab `.tfvars` file or a small version-specific module.

## Credentials

Do not commit administrator credentials.

Configure the provider using the environment variables/authentication mechanism supported by the official provider for your PingFederate deployment.

Inject the OAuth client secret separately:

```bash
export TF_VAR_token_exchange_client_secret='...'

PingFederate returns only an encrypted representation of an existing client
secret. Terraform therefore ignores drift only for `client_auth.secret` and
`client_auth.encrypted_secret`; the authentication type and all other client
settings remain managed. To rotate the secret, change the injected value and
explicitly replace only the OAuth client:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-pf-terraform.ps1 replace-client
```

This briefly recreates the lab client, so coordinate consumers of the old
secret before running it.
```

Do not place it in a committed tfvars file.

## Usage

```bash
cd deploy/pingfederate/terraform

cp terraform.tfvars.example terraform.tfvars
# Fill the PF 13.1 plugin descriptor/config values.

terraform init
terraform fmt -check
terraform validate
terraform plan
terraform apply
```

## Expected dependency flow

```text
subject token processor ----+
                            |
actor JWT processor --------+--> TEPP --> ATM mapping --> transaction JWT
                            |
OAuth client ---------------+
```

## SPIRE actor token

The local demo agent obtains a JWT-SVID with audience:

```text
urn:pingfederate:wai:token-exchange
```

The actor token processor must validate:

- SPIRE JWT signature,
- expected SPIFFE JWT issuer,
- required actor audience,
- expiry,
- workload subject (`sub`).

## Next Terraform milestone

Add a version-specific PF 13.1 lab module that fills the plugin descriptors/configuration automatically once the exact server plugin descriptor payloads are captured.

Then implement a trusted AgentID mapping source so:

```text
spiffe://example.org/agent/demo
          |
          v
urn:agent:demo
```

is derived inside the trusted PingFederate policy rather than accepted from the client.


## Plugin discovery is now automated

Before the first `terraform plan` against a PingFederate 13.1 server:

```bash
export PF_ADMIN_URL='https://localhost:9999/pf-admin-api/v1'
export PF_ADMIN_USERNAME='administrator'
export PF_ADMIN_PASSWORD='...'

make pf-discover
make pf-generate-tfvars
```

Review:

```text
deploy/pingfederate/discovered/wai-plugin-report.json
```

Then fill the plugin-specific configuration fields in a local ignored tfvars
file and set:

```hcl
discovery_confirmed = true
```

Terraform has a precondition that prevents token-processor creation until this
review gate is explicitly enabled.
