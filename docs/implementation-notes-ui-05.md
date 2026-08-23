# UI-05 implementation notes

Acceptance criteria: add a bounded in-memory interaction audit store and an
mTLS collector API; fan operational events to stdout and the required
collector with fail-closed behavior; derive submitting workload and query
ownership at trusted server boundaries; and reject spoofed identities,
oversized or unknown data, credential-shaped fields, collector write failure,
cross-user access, guessed IDs, and expired or over-capacity records.

The collector accepts submissions only from an exact configured SPIFFE ID
allowlist after certificate-chain verification. `SubmittingSPIFFEID` is always
overwritten from the peer certificate and is not part of the accepted JSON
schema. Service workloads are trusted producers: they derive user,
transaction, logical-agent, original-workload, and immediate-caller fields
from already verified transaction middleware. A compromised allowlisted
service can emit false audit metadata; preventing that requires signed event
attestation and is outside this in-memory MVP boundary.

The browser cannot query the collector. Only the exact web-app SPIFFE workload
may query it over mTLS, and the BFF supplies the user ID exclusively from its
server-side authenticated session. Both list and detail lookups filter on that
user. A guessed record or TransactionID belonging to another user returns the
same not-found result as an absent record.

Stored records have only fixed typed fields: correlation and verified identity
metadata plus method, tool, purpose, response status, result type, duration,
decision, and reason code. There are no maps for headers, arguments, or raw
request/response bodies. Field length, body size, event count, duration,
retention, event types, decisions, and status ranges are bounded. Token-like,
OAuth-secret-like, and private-key-like values are rejected before storage.

When configured, each workload uses a required fanout sink: JSON stdout first,
then the collector over SPIFFE mTLS with an explicit timeout. Any required sink
failure is returned to the existing middleware, runner, or gateway, which
already fails the allowed operation closed.
