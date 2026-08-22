# Implementation Notes: Tasks 11–12

Middleware authorizes only the conjunction of a verified typed transaction,
one SPIFFE URI from a verified TLS chain, and explicit caller policy. Missing or
ambiguous bearer credentials, TLS chains, URI identities, and bindings fail
closed. Handlers receive typed identity context and never parse JWTs.

SPIFFE HTTP client/server helpers use rotating X.509 sources and require an
explicit exact peer policy. No authorize-any production helper exists. Network
timeouts are mandatory for clients.
