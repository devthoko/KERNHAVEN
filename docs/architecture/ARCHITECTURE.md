# Kernhaven Architecture

Status: Draft v0.1 (M0). Decisions are recorded in [ADRs](../adr/README.md).

## 1. Processes and trust boundaries

```
                    ┌──────────────────────── Host (Debian 13) ─────────────────────────┐
 Browser ──TLS──▶   │ Caddy (caddy user)                                                 │
                    │   │ HTTP, 127.0.0.1 only                                           │
                    │   ▼                                                                │
                    │ kernhaven-core (kernhaven user, no extra privileges)     TB-2      │
                    │   │  SQLite /var/lib/kernhaven/kernhaven.db                        │
                    │   │                                                                │
                    │   │ unix socket /run/kernhaven/agent.sock (peer-cred + signed grant)│
                    │   ▼                                                      TB-3      │
                    │ kernhaven-agent (kernhaven-agent user, docker group, narrow caps)  │
                    │   ├──▶ Docker Engine (/run/docker.sock)                            │
                    │   ├──▶ systemd (D-Bus, polkit rules for kernhaven-* units only)    │
                    │   ├──▶ Caddy admin API (unix socket)                               │
                    │   └──▶ Disks / allow-listed file roots                             │
                    └────────────────────────────────────────────────────────────────────┘
 TB-1: Internet/LAN ↔ Caddy      TB-2: Caddy ↔ Core      TB-3: Core ↔ Agent      TB-4: Agent ↔ host resources
```

The Core is the policy decision point; the agent is an independent policy
enforcement point. A compromised Core must not be able to make the agent perform
operations outside the allow-list or without a valid grant (see
[Threat Model](../security/THREAT-MODEL.md) and ADR-0003).

## 2. Core modules (Go modular monolith)

Each module lives under `internal/core/<module>`, owns its tables and exposes a
Go interface to other modules. Modules never read other modules' tables.

| Module | Responsibility | Milestone |
|---|---|---|
| `platform/config` | Load and validate configuration | M1 |
| `platform/logging` | Structured JSON logging (`log/slog`) | M1 |
| `platform/store` | SQLite access, migrations, transactions | M1 |
| `platform/httpserver` | HTTP server, routing, middleware, error model | M1 |
| `platform/health` | Liveness, readiness, version | M1 |
| `identity` | Users, credentials, sessions, CSRF | M2 |
| `authz` | Roles, permissions, route permission registry | M2 |
| `audit` | Hash-chained audit log | M2 |
| `jobs` | Persistent job queue, step journal, recovery | M3 |
| `agentclient` | Typed client for agent operations, grant signing | M4 |
| `webui` | Embedded SPA assets | M5 |
| `containers` | Container, image, volume, network management | M6 |
| `policy` | Container policy engine | M6 |
| `stacks` | Compose import, validation, revisions, deploy | M7 |
| `catalog` | App store sources, signature verification | M8 |
| `apps` | App lifecycle (install, update, remove) | M8 |
| `storage` | Disks, filesystems, mounts | M9 |
| `files` | File manager | M10 |
| `mfa` | WebAuthn, TOTP, step-up | M11 |
| `network` | Routes, Caddy configuration | M12 |
| `certs` | Certificate management | M13 |
| `metrics` | Metrics collection and retention | M14 |
| `notify` | Notification channels and alert rules | M15 |
| `backup` | Encrypted backups, schedules, restore | M16 |
| `security` | Security dashboard aggregation | M17 |
| `upgrade` | Release verification, upgrade, rollback | M18 |

## 3. Agent

- Separate binary `kernhaven-agent`, separate system user and systemd unit.
- Two roles of the same binary, each with its own unit, socket and allow-list
  (M9, ADR-0022): the Docker agent (`kernhaven-agent` user, `docker` group, no
  capabilities) and the storage service (root with `SYS_ADMIN`/`SYS_RAWIO`
  only, disk inventory, formatting and mount units, nothing else).
- Listens only on a unix socket; accepts connections only from the `kernhaven`
  user (`SO_PEERCRED`).
- Every request is a typed operation (`containers.start`, `mounts.create`, …)
  with a strongly typed, validated payload. There is no generic "exec" or
  "docker passthrough" operation.
- Every request carries a short-lived grant signed by the Core (Ed25519),
  binding operation, target, actor and expiry. The agent verifies signature,
  expiry, replay (nonce cache) and its own allow-list. A per-operation local
  policy is evaluated in the agent independently of the Core.
- Detailed design in M4.

## 4. API

- REST + JSON under `/api/v1/`, described in `api/openapi/v1.yaml`
  (contract tests keep handlers and spec in sync).
- Server-Sent Events for live status (`/api/v1/events`).
- Error model: `{"error": {"code": "...", "message": "...", "request_id": "..."}}`.
  Internal error details are logged, never returned.
- Breaking changes require `/api/v2/`.

## 5. Repository structure

```
.
├── CLAUDE.md                     Engineering rules for AI agents
├── README.md
├── go.mod / go.sum
├── cmd/
│   ├── kernhaven-core/           Core entry point
│   └── kernhaven-agent/          Agent entry point (M4)
├── internal/
│   ├── platform/                 Shared foundation (config, logging, store, httpserver, health, version)
│   ├── core/<module>/            Core domain modules (M2+)
│   └── agent/                    Agent implementation (M4)
├── api/openapi/v1.yaml           Versioned API contract
├── web/                          React + TypeScript + Tailwind SPA (M5)
├── deploy/
│   ├── systemd/                  Hardened unit files
│   └── config/                   Example configuration
├── packaging/                    .deb packaging and install scripts (M18)
├── test/
│   ├── integration/              Real-service tests (Docker, Caddy, systemd)
│   └── e2e/                      Playwright browser tests (M5)
├── scripts/                      Developer and CI scripts
├── docs/
│   ├── product/                  Specification, feature matrix
│   ├── architecture/             This document
│   ├── security/                 Threat model
│   ├── adr/                      Architecture decision records
│   ├── testing/                  Test strategy
│   ├── milestones/               Milestone graph and per-milestone designs
│   └── release/                  Quality gates
└── .github/workflows/            CI pipelines
```

`internal/platform` was chosen over `internal/core/platform` because the agent
reuses config, logging and version packages.

## 6. Cross-cutting conventions

- Go: standard library first; every dependency needs a justification in an ADR
  or the milestone design.
- Explicit types for privileged operations (no `map[string]any` payloads).
- All filesystem paths from users are validated against allow-listed roots
  with symlink resolution (`openat2`/`RESOLVE_BENEATH` where available).
- Context deadlines on every outbound call.
- Time is UTC in storage, ISO 8601 in APIs.
