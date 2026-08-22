# Implementation Notes: Task 06

Acceptance criteria: resolve a verified SPIFFE ID to its trusted logical Agent
ID; accept known mappings; reject unknown workloads and conflicting mappings;
and prevent a caller-supplied Agent ID from overriding trusted resolution.

Trust boundary: registry bindings are operator-provided policy loaded before
serving requests. Lookup accepts only the authenticated SPIFFE ID. There is no
Agent ID input at the request-time resolution boundary, so an untrusted caller
cannot select a logical agent. SPIFFE IDs are parsed canonically and unknown,
malformed, duplicate, or conflicting bindings fail closed.
