# Implementation Notes: Task 22

Acceptance criteria: build and test supported commands for Windows, validate
the configurable Windows named-pipe Workload API form, retain Linux builds, and
avoid claiming parity without a native end-to-end run.

The validation script restores the caller's `GOOS` and `GOARCH`. The
Windows-only endpoint test rejects remote named-pipe addresses. Documentation
states the exact remaining native integration limitation.
