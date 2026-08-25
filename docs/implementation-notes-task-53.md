# Task 53 implementation notes

## Acceptance criteria restatement

Configure the isolated logical TTS only after runtime and descriptor attestation
succeeds. Reach port 9999 through a bounded private channel and never create an
administrator Ingress. Verify the exact product version and plugin class names
before plan or apply. Configure the strict processors, TEPP, ATM, scope, OAuth
clients, signing configuration, and exact workload bindings. Keep administrator
and OAuth credentials out of arguments, output, plans, committed tfvars, and
shared state. Reject wrong version, missing actor processor, unknown descriptor,
forged AgentID, wrong SPIFFE ID, missing audience, and drift ambiguity without
weakening validation.

## The gap this task actually had

Terraform configuration existed, but the only committed launcher,
`scripts/run-pf-terraform.ps1`, targets the Docker harness: it reads
`.env.local`, writes the default state in `deploy/pingfederate/terraform/`, and
runs `terraform apply` without `-auto-approve`. Running it against Kubernetes
therefore did three unsafe things at once. It mixed two servers' state in one
lineage, it depended on an operator-managed port-forward that nothing verified,
and a detached run blocked forever on the interactive approval prompt while
holding the state lock.

That last failure was observed: an apply left running without a terminal held
the lock for over twenty minutes at zero CPU, making every later Terraform
command fail with an unreadable state file.

## Implementation

`scripts/run-pf13-kubernetes-terraform.ps1` is the private channel.

- It refuses any namespace, release, or pod other than the reviewed isolated
  one, so the shared 12.3 release cannot be selected even by argument.
- It opens a bounded loopback port-forward on a random free port and stops it in
  `finally`. No administrator Ingress is created and port 9999 is never bound to
  a routable address.
- It verifies the administrator TLS leaf against the CA exported by
  `export-pf13-kubernetes-admin-ca.ps1`, and refuses `PF_ADMIN_INSECURE=true`.
- Administrator and OAuth client secrets are read from the exact
  Vault-synchronized Kubernetes Secrets into process environment only, and every
  name is removed in `finally`. No secret is ever a command-line argument.
- State is `deploy/pingfederate/generated/pf13-kubernetes.tfstate`, distinct in
  lineage from the Docker harness state. The gate refuses to run if it is absent
  rather than silently creating a fresh one against a configured server.
- `plan` writes a saved plan; `apply` consumes that saved plan. An unreviewed
  diff cannot be applied, and `-input=false` means no command can block on a
  prompt.

`deploy/pingfederate/scripts/attest_pf13_runtime.py` is the attestation. It
fails closed unless `/version` matches exactly `13.1` and each reviewed plugin
class resolves to exactly one descriptor: the SPIFFE JWT token processor, the
OAuth bearer subject processor, the exact-TTL transaction ATM, and the HTML form
adapter. Zero matches and more than one match are both rejected, because an
ambiguous descriptor cannot be bound to a reviewed contract. Failures report the
path and status only; response bodies and descriptor payloads are never printed.

`deploy/pingfederate/terraform/kubernetes.tfvars` is the reviewed, secret-free
input. It is committed so the deployment is reviewable, and it contains no
credential, key, or Vault value.

## Configuration defects this exposed

Attestation passed immediately, but configuring the attested runtime surfaced
four real defects. Each is recorded here because each was a live
misconfiguration, not a Terraform mechanics problem.

**The runtime base URL was an internal engine address.** PingFederate renders
every hosted page against its configured base URL. With
`https://localhost:9031`, the hosted login page emitted
`<base href="https://localhost:9031/">` and a root-relative form action, so a
browser resolved both the stylesheet and the credential POST back to an address
it cannot reach. The login page rendered and could never be submitted. The base
URL is now the external HTTPS origin, in `server_settings.tf`.

That change has a second, deliberate benefit. The base URL is the issuer of the
tokens this logical TTS signs. It was previously identical to the Docker
harness's issuer string, so two distinct signers shared one issuer identifier
while `AGENTS.md` requires issuers to be allowlisted. They are now distinct.

**The ATM issuer was configured independently of the base URL.** It is now
derived from `var.pf_base_url`, so a consumer that allowlists the PingFederate
origin has allowlisted exactly one issuer and the two cannot drift.

**Kubernetes never enabled the strict inner Transaction Token profile.** Every
deployed workload implements only that profile, requesting the trust domain as
the audience and the strict scope. PingFederate was still configured for the
legacy WAI JWT, so the exchange returned 400. The capability probe is a
precondition of the inner profile, not an optional diagnostic, so both flags are
set together in the reviewed variable file.

**The actor token processor trusted another environment's SPIRE keys.** Its
JWKS held the Docker lab's EC P-256 authorities while the in-cluster SPIRE signs
with RSA. The gate now reads the bundle from the SPIRE server that actually
attests these workloads, so the trust anchor cannot be inherited from elsewhere
and a rotated JWT authority is picked up by re-running the gate.

Translating that bundle is not a copy. SPIRE marks JWT authorities
`use: "jwt-svid"`, which a JOSE verification-key selector will not consider,
and its X.509 authorities carry no key ID at all. The gate selects only the JWT
authorities, requires a unique non-empty key ID on each, copies only public
material, and pins `alg` per key type rather than letting a token header select
one. A key type outside the reviewed RS256/ES256 allowlist is rejected. This
mirrors what the reviewed Docker exporter already did, extended to RSA.

`terraform_atm` scope provisioning also had to move into the gate: PingFederate
rejects a client that restricts an undefined scope, and Terraform does not own
the OAuth server's scope collection. The gate provisions the two approved fixed
scopes through the existing create-only helper, which refuses any scope outside
its allowlist.

## What was not weakened

The 300 second actor token lifetime bound was not raised to accommodate the
cluster's one hour default JWT-SVID TTL. The registration was pinned instead;
see [Task 57](implementation-notes-task-57.md). No caller-supplied field became
authoritative, no validation was relaxed, and the TEPP still leaves `agent_id`,
`agent_instance_id`, `transaction_id`, and `transaction_purpose` unmapped so the
trusted ATM remains the only source of those values.
