# Windows Validation

Task 22 validates the platform-neutral Go packages and all four command targets
on Windows, then cross-builds the same commands for Linux AMD64.

Run from PowerShell:

```powershell
go test ./...
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-platforms.ps1
```

The supported Windows SPIRE Workload API endpoint form is:

```text
npipe:spire-agent/public/api
```

The endpoint stays in configuration and is passed to `go-spiffe`; application
and domain packages do not translate it into a Unix socket. A Windows-only test
accepts the local named-pipe form and rejects a remote-host pipe.

## Validation boundary

This task establishes Windows compilation, native unit tests, and named-pipe
address validation. The repository's Docker Compose lab runs Linux containers
inside Docker Desktop and therefore does not constitute a native Windows SPIRE
Agent end-to-end test. Do not claim native Windows end-to-end parity until a
Windows SPIRE Agent has attested the commands and completed the transaction
flow.
