# Implementation Notes: Task 28

## Acceptance criteria

A clean checkout can build the PingFederate profile without a committed copy
of PingFederate's SDK libraries. Missing dependencies are extracted from the
same immutable image digest used by local runtime Compose.

## Trust boundary

The vendor image is an external executable and artifact boundary. The
extractor pins its immutable digest and copies only four fixed public JAR paths
needed to compile the custom plugin. It does not inspect or copy `/opt/out`,
licenses, secrets, certificates, keys, configuration, or state.

The temporary container name includes the current process ID. The extractor
refuses to reuse an existing container with that exact name and its cleanup can
remove only that script-owned name. Each result must exceed the minimum size
and begin with the ZIP/JAR magic bytes before Maven can use it.

## Failure coverage

Tests require the image digest, fixed library path, unique temporary name,
minimum-size and JAR-magic checks, exact cleanup target, and absence of edge,
latest, credential, or DevOps-secret references.
