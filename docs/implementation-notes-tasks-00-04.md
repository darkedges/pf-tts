# Implementation Notes: Tasks 00–04

## Task 00 — Repository baseline

Acceptance criteria: the Go module and initial portable directory structure compile under `go test ./...`; application code has no Kubernetes dependency; the README, contributor rules, and architecture documentation exist. No CI workflow is added in this task.

## Task 01 — Core identity model

Acceptance criteria: strongly typed user, logical agent, workload, transaction, authorization, and request identity structures have validating constructors; logical Agent ID and SPIFFE ID remain separate; domain structures contain no raw credentials; empty or malformed identifiers fail tests.

Trust boundary: these types represent identity only after a caller at a cryptographic or trusted-configuration boundary has established it. Constructors reject missing values but do not claim to authenticate caller input. Failure tests ensure incomplete identities cannot form a request identity context.

## Task 02 — Configuration model

Acceptance criteria: JSON/YAML-tagged configuration models server, SPIFFE, PingFederate, transaction, agents, MCP, and audit sections; validation requires issuer, token endpoint, audience, bounded positive TTLs, and unambiguous agent/workload bindings. Environment loading is deliberately deferred.

Trust boundary: agent-to-workload bindings are trusted operator policy, not request data. Duplicate Agent IDs and duplicate SPIFFE bindings fail closed so ambiguous policy cannot select an identity. Tests cover all required rejection paths.

The product safety ceiling for transaction TTL is 60 seconds. The example remains at 20 seconds with a configured maximum of 30 seconds, matching the security model's short-lived bearer-token guidance.

## Task 03 — SPIFFE provider interface

Acceptance criteria: the core boundary fetches JWT-SVIDs for explicit audiences, obtains a closeable X.509 source suitable for mTLS, exposes the selected SPIFFE ID, and closes resources. A fake exercises the interface without requiring a SPIRE Agent. The go-spiffe adapter remains deferred to Task 05.

Trust boundary: the provider implementation, not an inbound request field, selects the SPIFFE identity returned by the Workload API. The core API makes audience input mandatory at the implementation boundary; the fake's failure test rejects an empty audience.

## Task 04 — Self-contained SPIRE lab

Acceptance criteria: pinned official SPIRE 1.15.2 Server and Agent images provide the `example.org` lab trust domain, development-only join-token attestation, Docker workload attestation, a shared Unix Workload API socket, four distinct label-selected registrations, and a labeled JWT probe requesting the PingFederate actor audience. Bootstrap creates fresh uncommitted bundle/token material, registration is idempotent, and documentation identifies the bootstrap and Docker socket risks.

Trust boundary: the SPIRE Agent derives workload identity from Docker-observed labels and registration policy. A workload cannot choose another SPIFFE ID in a request. Tests fail if required distinct selectors, the probe label/audience, generated-material ignore rule, or lab-only warning disappears.

Fresh Docker named volumes and the Docker Engine socket are root-owned. The development lab therefore runs the SPIRE containers as root so the server can initialize SQLite and the agent can attest Docker workloads. The agent uses the host PID namespace to correlate Workload API peer processes with Docker containers. These elevated privileges are explicitly confined to the local lab and tested for a production warning; production must provision least-privilege storage and attestor access.

SPIRE 1.15.2 reserves `/spire/agent/` for node attestors. Join-token attestation derives the node identity as `spiffe://example.org/spire/agent/join_token/<token-id>` and rejects a caller-forced `spiffe://example.org/spire/agent/local-lab`. Bootstrap therefore records only the derived non-secret parent ID in ignored generated material, while registration validates its exact trust-domain/attestor shape and fails on missing or unexpected values. The one-time join token is never persisted.

The probe CLI's raw response contains the JWT-SVID. The wrapper holds that response only in memory, checks the expected subject and actor audience, and prints safe metadata only. Claim decoding here is solely an integration assertion after retrieval from the local Workload API; it is not an authorization path and does not replace signature validation.
