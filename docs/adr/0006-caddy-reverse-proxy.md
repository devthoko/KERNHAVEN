# ADR-0006: Caddy as TLS terminator and reverse proxy

- Status: Accepted
- Date: 2026-10-27

## Decision
Caddy 2 terminates TLS for Kernhaven and installed apps and provides ACME and an
internal CA. Kernhaven manages Caddy through its admin API on a unix socket,
reachable only by the agent. Configuration is validated before apply and the
previous configuration is kept for rollback.

## Consequences
The Core listens on loopback only (ADR-0010). Caddy becomes part of the trusted
computing base; its version is tracked in release notes.
