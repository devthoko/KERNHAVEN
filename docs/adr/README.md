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
| [0013](0013-signed-releases.md) | Signed and verifiable releases | Accepted (key ceremony open, B-3) |
| [0014](0014-ci-supply-chain-pinning.md) | CI actions pinned by commit SHA | Accepted |
| [0015](0015-argon2id-password-hashing.md) | Argon2id password hashing via golang.org/x/crypto | Accepted |
| [0016](0016-hash-chained-audit-log.md) | Hash-chained audit log in SQLite | Accepted |
| [0017](0017-minimal-docker-client.md) | Minimal Docker Engine API client instead of the Docker SDK | Accepted |
| [0018](0018-compose-subset-yaml-v3.md) | Own Compose parser on gopkg.in/yaml.v3 for a supported subset | Accepted |
| [0019](0019-secret-encryption.md) | AES-256-GCM encryption for stack variables | Accepted |
| [0020](0020-signed-catalogs.md) | Ed25519-signed JSON catalogs with per-source trust keys | Accepted |
| [0021](0021-volume-snapshots-helper.md) | Volume snapshots with an agent-built helper container | Accepted |
| [0022](0022-host-tools-and-mount-units.md) | Fixed host tools for storage, systemd mount units, separate storage service | Accepted |
| [0023](0023-file-access-and-streaming.md) | File access through os.Root in a separate file service, streamed | Accepted |
| [0024](0024-webauthn-library-and-totp.md) | go-webauthn for passkeys, TOTP implemented in-house | Accepted |
| [0025](0025-caddy-configured-by-proxy-service.md) | Caddy in its own unit, configured only by a proxy service from typed routes | Accepted |
| [0026](0026-certificates.md) | Certificates: Caddy for internal and HTTP-01, the Core for DNS-01 | Accepted |
| [0027](0027-monitor-role-and-metric-storage.md) | A monitor role for host readings; metrics in SQLite with fixed downsampling | Accepted |
| [0028](0028-notification-channels.md) | Notification channels without SDKs, LAN destinations allowed, dial-time address checks | Accepted |
| [0029](0029-backup-format.md) | Own backup format: STREAM encryption with AES-256-GCM, Argon2id-wrapped key | Accepted |
| [0030](0030-backup-targets-and-volume-streams.md) | Backup targets (local, SFTP with pinned host keys, own S3 client) and volume streams through the Docker agent | Accepted |
| [0031](0031-console-and-live-streams.md) | A line console and live updates over server-sent events | Accepted |
| [0032](0032-packages-and-upgrades.md) | Debian packages, an idempotent installer and a CLI upgrader with automatic rollback | Accepted |
| [0033](0033-web-ui-information-architecture.md) | Web UI: areas with tabs, apps-first home, own icon set | Proposed |
