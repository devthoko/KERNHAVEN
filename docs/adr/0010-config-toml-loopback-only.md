# ADR-0010: TOML configuration, loopback-only Core listener

- Status: Accepted
- Date: 2026-10-27

## Decision
- Configuration is a TOML file (`/etc/kernhaven/core.toml`), decoded strictly:
  unknown keys are errors, not warnings.
- Dependency: `github.com/BurntSushi/toml` (small, widely used, no transitive
  dependencies).
- The Core HTTP listener must bind to a loopback address. Non-loopback binds
  are rejected; external access is only via Caddy.
- The data directory must be an absolute path, owned by the service user and
  not accessible by group or others (mode 0700).

## Consequences
Misconfiguration fails fast at startup (AT-F00-01). Exposing the Core directly
to the network requires a code change and a new ADR, not a config flag.
