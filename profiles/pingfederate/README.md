# PingFederate server profile

This public, parameterized server profile is consumed with:

```text
SERVER_PROFILE_URL=https://github.com/darkedges/pf-tts.git
SERVER_PROFILE_PATH=profiles/pingfederate
SERVER_PROFILE_BRANCH=main
```

The profile contains configuration placeholders only. Do not add `env_vars`,
credentials, certificates, JWKs, private keys, licenses, Terraform state, or
generated exports. Kubernetes supplies each required placeholder from a
reviewed Vault-synchronized Secret key at runtime. The tested custom plugin JAR
is baked into the derived PingFederate image and is not stored here.
