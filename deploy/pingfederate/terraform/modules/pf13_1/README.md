# PingFederate 13.1 Lab Profile

This directory records the PingFederate 13.1-specific discovery contract.

Do not hard-code guessed plugin configuration field names. Run:

```bash
make pf-discover
make pf-generate-tfvars
```

The discovery process reads these supported Admin API endpoints:

```text
GET /pf-admin-api/v1/version
GET /pf-admin-api/v1/idp/tokenProcessors/descriptors
GET /pf-admin-api/v1/oauth/accessTokenManagers/descriptors
```

It stores the exact plugin descriptor payloads under:

```text
deploy/pingfederate/discovered/
```

The generated `pf13_1.auto.tfvars.json` pins the discovered plugin IDs but leaves
`discovery_confirmed=false` until the descriptor fields have been reviewed.

The JWT access token manager plugin ID commonly documented by the official
provider is:

```text
com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin
```

Discovery remains authoritative for the target PingFederate server.
