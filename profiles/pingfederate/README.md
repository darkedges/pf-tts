# PingFederate server profile

This public, parameterized server profile is consumed with:

```text
SERVER_PROFILE_URL=https://github.com/darkedges/pf-tts.git
SERVER_PROFILE_PATH=profiles/pingfederate
SERVER_PROFILE_BRANCH=main
```

This Task 52 startup profile contains the public post-fetch hook that moves
the baked, tested plugin JAR from the readable `/opt/in` root into PingFederate's
supported staging deploy directory. The vendor startup hook creates the
administrator directly from the Vault-injected `PING_IDENTITY_PASSWORD`. The
full bulk profile must retain that exact lowercase account, its roles, and the
same required environment placeholder because PingFederate otherwise removes
the account or rejects the import. The secret value remains on the documented
Vault-to-container bootstrap boundary and is never stored in this repository.
Task 53 configures scopes, processors,
policies, token managers, mappings, and clients through Terraform only after
descriptor attestation succeeds.

Do not add `env_vars`, general bulk exports, credentials, certificates, JWKs, private
keys, licenses, Terraform state, or generated files. The tested custom plugin
JAR is baked into the derived image and is not stored here.
