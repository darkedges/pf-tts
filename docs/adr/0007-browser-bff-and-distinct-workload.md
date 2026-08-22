# ADR 0007: Browser BFF and Distinct Workload Identity

## Status

Accepted for the authenticated application UI.

## Context

A browser cannot safely hold the subject access token, actor JWT-SVID, OAuth
client secret, or short-lived transaction token. Reusing the demo agent's
logical or workload identity would also collapse two independently deployed
actors and allow policy or audit records to confuse their origin.

## Decision

Use a backend-for-frontend for browser authentication and delegated service
invocation. PingFederate hosts credential entry. The browser receives only an
opaque server-side session identifier in a secure cookie.

The BFF is bound through trusted configuration as:

```text
AgentID:  urn:agent:web-app
SPIFFEID: spiffe://example.org/agent/web-app
```

The audit collector is a separate workload:

```text
SPIFFEID: spiffe://example.org/audit/collector
```

Neither identity may be selected by browser input, and the two workloads may
not share a SPIFFE ID.

## Consequences

PingFederate, SPIRE, and OPA require explicit web-app bindings. Browser OAuth
uses a dedicated client rather than either existing lab client. Sessions and
audit storage need bounded server-side state. This adds two workloads but keeps
credentials and cryptographic workload material outside the browser and makes
authorization and audit attribution unambiguous.
