# Implementation Notes: Task 30

Acceptance criteria: select only repository-owned PingFederate application
objects, externalize their credentials, reject ambiguous or residual sensitive
configuration, and leave Terraform as the sole configuration authority.

## Trust boundary

The raw Admin API export is untrusted generated input even though it came from
an authenticated local server: it includes privileged global configuration and
may include changes made outside this repository. Selection therefore requires
both an exact resource type and an exact object ID. Singleton resources must
occur exactly once. Unknown and missing application objects fail the build.

The candidate includes login, OAuth client, token processor, access-token
manager, mapping, OIDC, token-exchange, and authentication-policy objects only.
It excludes administrative accounts, licenses, key pairs, TLS certificates,
signing material, system keys, server settings, and global OAuth settings.

Encrypted credential fields are changed to external substitutions by the
converter. A second validation rejects remaining encrypted field names,
literal `password` or `secret` values, and private-key PEM data.

## Configuration ownership

Bulk import overwrites PingFederate admin configuration. The generated
`data.json.subst` remains an ignored review candidate and is neither mounted nor
imported. Terraform remains authoritative. Promoting this candidate would
require a separate ADR, removal of overlapping Terraform ownership, a complete
secret-input inventory, and a clean-volume failure-matrix test.
