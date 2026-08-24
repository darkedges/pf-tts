# PingFederate server profile

This public, parameterized server profile is consumed with:

```text
SERVER_PROFILE_URL=https://github.com/darkedges/pf-tts.git
SERVER_PROFILE_PATH=profiles/pingfederate
SERVER_PROFILE_BRANCH=main
```

This Task 52 startup profile contains only the public post-fetch hook that moves
the baked, tested plugin JAR from the readable `/opt/in` root into PingFederate's
supported staging deploy directory. Task 53 configures scopes, processors,
policies, token managers, mappings, and clients through Terraform only after
descriptor attestation succeeds.

Do not add `env_vars`, bulk exports, credentials, certificates, JWKs, private
keys, licenses, Terraform state, or generated files. The tested custom plugin
JAR is baked into the derived image and is not stored here.
