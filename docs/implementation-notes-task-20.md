# Implementation Notes: Task 20

Acceptance criteria: provide an app-only profile that connects runnable demo
services to external PingFederate and SPIRE endpoints, plus a local-lab profile
that includes the demo agent. Secrets remain environment-injected and neither
PingFederate nor SPIRE is embedded into application code.

The four command targets build into a minimal non-root image. Each container
has one Docker workload label and selects one exact expected SPIFFE ID. Server
and client peers use exact SPIFFE allowlists. Compose contains required
environment references, not credential values.
