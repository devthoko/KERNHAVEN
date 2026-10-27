# Architecture Decision Records

Format: [MADR](https://adr.github.io/madr/)-style, one decision per file,
numbered sequentially. Accepted ADRs are immutable; a change of mind is a new
ADR that supersedes the old one.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-go-modular-monolith.md) | Go modular monolith for the Core | Accepted |
| [0003](0003-separate-host-agent.md) | Separate privilege-restricted host agent | Accepted |
| [0004](0004-sqlite-persistence.md) | SQLite for single-node persistence | Accepted |
| [0005](0005-docker-access-only-via-agent.md) | Docker Engine access only via the agent | Accepted |
| [0006](0006-caddy-reverse-proxy.md) | Caddy as TLS terminator and reverse proxy | Accepted |
| [0007](0007-react-typescript-tailwind-spa.md) | React + TypeScript + Tailwind SPA embedded in the Core | Accepted |
| [0008](0008-native-systemd-deployment.md) | Native systemd deployment | Accepted |
| [0009](0009-pure-go-sqlite-driver.md) | Pure-Go SQLite driver | Accepted |
| [0010](0010-config-toml-loopback-only.md) | TOML configuration, loopback-only Core listener | Accepted |
| [0011](0011-checksummed-embedded-migrations.md) | Embedded, checksummed, forward-only migrations | Accepted |
| [0012](0012-versioned-rest-api-openapi.md) | Versioned REST API with OpenAPI contract | Accepted |
| [0013](0013-signed-releases.md) | Signed and verifiable releases | Proposed |
| [0014](0014-ci-supply-chain-pinning.md) | CI actions pinned by commit SHA | Accepted |
| [0015](0015-argon2id-password-hashing.md) | Argon2id password hashing via golang.org/x/crypto | Accepted |
| [0016](0016-hash-chained-audit-log.md) | Hash-chained audit log in SQLite | Accepted |
