# Implementation Notes: Task 21

Acceptance criteria: automate the valid identity chain and transaction-ID
continuity, plus rejection of forged AgentID, wrong workload, wrong audience,
expired or missing tokens, an unapproved target, and an agent calling the API
directly. Captured audit output must not contain bearer material.

The test uses the same production middleware and typed identity context at all
three hops. Cryptographic JWT cases remain covered by the verifier suite; this
chain test isolates caller binding, immutable context, and routing decisions.
