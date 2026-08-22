# Implementation Notes: Task 23

Acceptance criteria: document every listed compromise and abuse scenario, then
record ADRs for immutable transaction context, independent immediate-caller
mTLS, PingFederate issuance, SPIRE workload identity, and separation of logical
AgentID from SPIFFEID.

The threat model states residual bearer replay risk and trust-anchor compromise
explicitly. It does not claim proof of possession, replay prevention, or native
Windows end-to-end parity.
