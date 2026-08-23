# PingAuthorize local server profile

This repository-owned overlay is mounted read-only at `/opt/in` and layered
with Ping's pinned getting-started profile. During first setup, its dsconfig
selects the repository-owned WAI deployment package from a separate read-only
mount.

The profile contains no credentials, licenses, private keys, or generated
trust material. PingAuthorize's `/opt/out` remains a named local-development
volume.
