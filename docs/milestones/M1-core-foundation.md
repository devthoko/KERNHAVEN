# M1 — Core Foundation

Status: In progress
Depends on: M0
Acceptance tests: AT-F00-01 … AT-F00-06 ([Feature Matrix](../product/FEATURE-MATRIX.md))

## Goal

A runnable, hardened `kernhaven-core` service that every later module builds on:
validated configuration, structured logging, SQLite with safe migrations, an
HTTP server with a secure baseline, health/version endpoints, graceful shutdown
and a hardened systemd unit. No user-facing features yet.

## Design

### Packages

| Package | Responsibility |
|---|---|
| `internal/platform/version` | Build metadata injected via `-ldflags` |
| `internal/platform/config` | TOML loading (strict), defaults, validation |
| `internal/platform/logging` | `slog` JSON handler, level from config |
| `internal/platform/store` | Open SQLite with pragmas, embedded checksummed migrations |
| `internal/platform/httpserver` | Router, middleware chain, JSON error model, server lifecycle |
| `internal/platform/health` | `live`, `ready`, `version` handlers |
| `cmd/kernhaven-core` | Wiring, signal handling, exit codes |

### Configuration (`/etc/kernhaven/core.toml`)

```toml
[server]
listen = "127.0.0.1:8470"        # must be a loopback IP literal or "localhost"
shutdown_timeout = "15s"          # 1s..120s
max_body_bytes = 1048576          # 1 KiB..64 MiB

[storage]
data_dir = "/var/lib/kernhaven"   # absolute, exists, directory, owned by process uid, mode without group/other bits

[log]
level = "info"                    # debug | info | warn | error
```

Validation rules (all produce a startup error and exit code 2):
unknown keys; invalid durations/sizes outside bounds; non-loopback listen
address; relative, missing, non-directory, foreign-owned or group/other
accessible data dir; unknown log level.

### Database

- File `<data_dir>/kernhaven.db`; pragmas: `journal_mode=WAL`,
  `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=5000`.
- Migrations embedded from `internal/platform/store/migrations/*.sql`, applied
  per ADR-0011. Table `schema_migrations(version, name, checksum, applied_at)`.
- M1 ships migration `0001_init.sql` creating `schema_migrations` metadata only
  via the runner plus a `instance` table holding a random instance ID created
  on first start (used later for audit chain and backup identification).
- Startup runs `PRAGMA quick_check`; failure aborts with exit code 3.

### HTTP

- Routes (method-specific, everything else 404/405 JSON):
  - `GET /api/v1/health/live` → `200 {"status":"ok"}`
  - `GET /api/v1/health/ready` → `200 {"status":"ok"}` or `503 {"status":"unavailable"}` when DB ping fails
  - `GET /api/v1/version` → `{"version","commit","build_date","go_version"}`
- Middleware order: request ID → access log → panic recovery → security headers → body limit.
- Security headers on every response: `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`, `Cache-Control: no-store`.
  HSTS is set by Caddy (TLS terminator), not by the Core.
- Server timeouts: ReadHeader 5 s, Read 30 s, Write 30 s, Idle 120 s, MaxHeaderBytes 16 KiB.
- Errors: `{"error":{"code","message","request_id"}}`.

### Process

- `kernhaven-core [-config path]` (default `/etc/kernhaven/core.toml`),
  `kernhaven-core version`.
- SIGINT/SIGTERM → `http.Server.Shutdown` with `shutdown_timeout`, then DB close.
- Exit codes: 0 ok, 1 runtime error, 2 config error, 3 database error.

### systemd unit

`deploy/systemd/kernhaven-core.service`: `User=kernhaven`, `StateDirectory`,
`ConfigurationDirectory`, `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, `CapabilityBoundingSet=`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service`,
`MemoryDenyWriteExecute`, `IPAddressDeny=any` + `IPAddressAllow=localhost`, etc.

## Acceptance criteria → tests

| AT | Test(s) |
|---|---|
| AT-F00-01 | `config` unit tests: each invalid case + valid default case; `cmd` test: exit code 2 on invalid config |
| AT-F00-02 | `store` tests: fresh migrate, idempotent re-open, checksum mismatch abort, newer-DB abort, failing migration rollback |
| AT-F00-03 | `health` + `httpserver` component tests incl. readiness 503 after DB close |
| AT-F00-04 | `httpserver` tests: headers, 404, 405, 413, panic → 500 without details |
| AT-F00-05 | `cmd` integration test: build binary, start, request, SIGTERM, assert clean exit 0 and in-flight request completes |
| AT-F00-06 | `systemd-analyze verify` + `systemd-analyze security` on the unit (needs systemd ≥ 252 host; runs in CI on Ubuntu runner) |

## Security considerations

- Mitigates TH-05 (loopback-only), TH-07 (no internal error leakage), TH-54
  (data dir permissions), partially TH-06 (timeouts, body limit) and TH-53
  (WAL, FULL sync, quick_check).
- No authentication exists yet. All M1 endpoints are intentionally
  unauthenticated and expose no sensitive data (version info is acceptable;
  revisit in M2 whether `/version` requires authentication — tracked).

## Known limitations

- No authentication/authorization (M2). Must not be exposed beyond loopback —
  enforced by config validation.
- Rate limiting is not implemented (M2).
- systemd unit is verified statically; installation is not tested until the
  installer exists (M18) and Debian 13 VMs are available (B-2).
- `-race` cannot run on the dev server (no C toolchain); it runs in CI.

## Verification procedure

```bash
go vet ./...
go test ./...
go test -race ./...          # CI or any host with gcc
go build -o bin/kernhaven-core ./cmd/kernhaven-core
mkdir -p /tmp/kh-data && chmod 700 /tmp/kh-data
cat > /tmp/kh.toml <<'EOF'
[storage]
data_dir = "/tmp/kh-data"
EOF
./bin/kernhaven-core -config /tmp/kh.toml &
curl -si http://127.0.0.1:8470/api/v1/health/ready
kill -TERM %1; wait
systemd-analyze verify deploy/systemd/kernhaven-core.service
systemd-analyze security --offline=true deploy/systemd/kernhaven-core.service
```
