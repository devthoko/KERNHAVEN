# ADR-0008: Native systemd deployment

- Status: Accepted
- Date: 2026-10-27

## Decision
Core and agent run as native systemd services with sandboxing
(`ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`,
restricted address families and system calls, `CapabilityBoundingSet=` empty
for the Core). Kernhaven does not run in a container.

## Consequences
Debian packages install units and users. Hardening is verified with
`systemd-analyze security` in CI/integration tests (AT-F00-06).
