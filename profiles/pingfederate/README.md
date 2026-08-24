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
administrator directly from the Vault-injected `PING_IDENTITY_PASSWORD`; the
bulk profile deliberately does not import or rotate administrative accounts.
This keeps the administrator credential on the documented container bootstrap
boundary and avoids treating a bulk-profile placeholder as password material.
Task 53 configures scopes, processors,
policies, token managers, mappings, and clients through Terraform only after
descriptor attestation succeeds.

Do not add `env_vars`, general bulk exports, credentials, certificates, JWKs, private
keys, licenses, Terraform state, or generated files. The tested custom plugin
JAR is baked into the derived image and is not stored here.
