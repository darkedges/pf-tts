# PingFederate server profile

This public, parameterized server profile is consumed with:

```text
SERVER_PROFILE_URL=https://github.com/darkedges/pf-tts.git
SERVER_PROFILE_PATH=profiles/pingfederate
SERVER_PROFILE_BRANCH=main
```

This Task 52 startup profile contains only the public post-fetch hook that moves
the baked, tested plugin JAR from the readable `/opt/in` root into PingFederate's
supported staging deploy directory. The vendor startup hook creates the native
administrator directly from the Vault-injected `PING_IDENTITY_PASSWORD`. There
is deliberately no startup bulk import because a full import replaces the
vendor-created administrative credential. Task 53 owns all product
configuration after authenticated version and descriptor attestation.
Task 53 configures scopes, processors,
policies, token managers, mappings, and clients through Terraform only after
descriptor attestation succeeds.

Do not add `env_vars`, bulk configuration, credentials, certificates, JWKs, private
keys, licenses, Terraform state, or generated files. The tested custom plugin
JAR is baked into the derived image and is not stored here.
