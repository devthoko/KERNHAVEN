# Kernhaven 1.0 Feature Matrix

This matrix is the single source of truth for 1.0 scope and acceptance tests.
Every row must reach **Done** before release. Acceptance test IDs (`AT-…`) are
referenced by test code and by the [Test Strategy](../testing/TEST-STRATEGY.md).

Status values: **Not started**, **In progress**, **Done** (all ATs automated and
passing on primary platforms), **Blocked** (blocker documented in the row).

Milestones are defined in [Milestones](../milestones/MILESTONES.md).

## Platform foundation (cross-cutting)

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F00-01 | Core starts from validated config | Invalid config (unknown key, relative path, non-loopback listen, insecure data dir permissions) is rejected at startup with a precise error and non-zero exit | M1 | Done |
| AT-F00-02 | Schema migrations | Fresh DB is migrated to latest; restart is idempotent; a modified already-applied migration is detected and startup aborts; a failing migration leaves the DB at the previous version | M1 | Done |
| AT-F00-03 | Health and version endpoints | `/api/v1/health/live`, `/api/v1/health/ready` and `/api/v1/version` respond; readiness fails when the DB is unavailable | M1 | Done |
| AT-F00-04 | Hardened HTTP baseline | Security headers present; unknown routes 404, wrong methods 405, oversized bodies 413, handler panics 500 without internal details | M1 | Done |
| AT-F00-05 | Graceful shutdown | SIGTERM drains in-flight requests within the configured timeout and closes the DB cleanly | M1 | Done |
| AT-F00-06 | Hardened systemd unit | Unit passes `systemd-analyze verify`; exposure score ≤ 2.0 in `systemd-analyze security` | M1 | Done |

## F01 — Modern, responsive web dashboard

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F01-01 | Embedded SPA served by Core | UI is served from the Core binary with a strict CSP (no inline script, no third-party origins) | M5 | Done (CI 40519204275; merge pending owner review) |
| AT-F01-02 | Responsive layout | All primary views usable at 360 px, 768 px and 1440 px widths (Playwright visual checks) | M5 | Done (CI 40519204275; merge pending owner review) |
| AT-F01-03 | Light and dark theme | Theme follows OS preference and can be overridden per user | M5 | Done (CI 40519204275; merge pending owner review) |
| AT-F01-04 | Accessibility | Automated axe checks pass with no serious/critical violations; keyboard-only navigation works | M5 | Done (CI 40519204275; merge pending owner review) |
| AT-F01-05 | Live status | Container/app status updates without page reload (SSE) | M6 | Moved to M6b (polling every 2–3 s in M6) |

## F02 — Complete Docker container management

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F02-01 | List and inspect | All containers, images, networks and volumes are listed with state from the real Docker Engine | M6 | Done (CI 40559956035; merge pending owner review) |
| AT-F02-02 | Lifecycle | Start, stop, restart, pause, unpause, remove work and are audited | M6 | Done (CI 40559956035; merge pending owner review) |
| AT-F02-03 | Logs | Streamed and historical logs with follow, tail and time range | M6 | Done (CI 40559956035; merge pending owner review) |
| AT-F02-04 | Create from spec | Create a container from a validated spec; policy violations (privileged, host PID/network, dangerous mounts, added capabilities) are rejected unless explicitly allowed by an Owner-approved exception | M6 | Done (CI 40559956035; merge pending owner review) |
| AT-F02-05 | Images | Pull (with digest pinning), list, remove, prune | M6 | Done (CI 40559956035; merge pending owner review) |
| AT-F02-06 | Volumes and networks | Create, inspect, remove; in-use resources cannot be removed | M6 | Done (CI 40559956035; merge pending owner review) |
| AT-F02-07 | Exec console | Interactive shell into a container for Admin+, audited, with session recording of metadata (not content) | M6 | Moved to M6b (needs bidirectional streaming design) |

## F03 — Docker Compose import, validation, editing and deployment

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F03-01 | Import | Import from file upload, paste and URL (HTTPS only, size-limited) | M7 | Implemented on `m7-compose`; CI pending |
| AT-F03-02 | Validation | Schema validation against the Compose specification with line-accurate errors | M7 | Implemented on `m7-compose`; CI pending |
| AT-F03-03 | Policy check | Container policy evaluation before deploy; violations block deploy and are explained | M7 | Implemented on `m7-compose`; CI pending |
| AT-F03-04 | Editor | In-browser editor with validation feedback and versioned history | M7 | Implemented on `m7-compose`; CI pending |
| AT-F03-05 | Deploy and redeploy | Deploy, update and tear down a stack; partial failure rolls back to the previous revision | M7 | Implemented on `m7-compose`; CI pending |
| AT-F03-06 | Secrets | Compose secrets/env values stored encrypted, never shown again after entry | M7 | Implemented on `m7-compose`; CI pending |

## F04 — Functional application store

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F04-01 | Catalog sync | Catalog fetched from configured sources; signature verified; unsigned or tampered catalogs are rejected | M8 | Not started |
| AT-F04-02 | Browse and search | Category, text search and app detail pages with required permissions shown | M8 | Not started |
| AT-F04-03 | Multiple sources | Owner can add/remove catalog sources with their own trust keys | M8 | Not started |
| AT-F04-04 | Policy disclosure | Each app shows the privileges it requests before install | M8 | Not started |

## F05 — App installation, updating and removal

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F05-01 | Install | Install with configuration form, generated secrets, reverse proxy route and health check | M8 | Not started |
| AT-F05-02 | Update | Update with pre-update snapshot; failed health check rolls back automatically | M8 | Not started |
| AT-F05-03 | Remove | Remove with choice to keep or delete data; deletion requires re-authentication | M8 | Not started |
| AT-F05-04 | Interrupted operations | Killing Core or agent mid-install/update resumes or rolls back cleanly on restart | M8 | Not started |

## F06 — Storage and disk management

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F06-01 | Inventory | Disks, partitions, filesystems, usage and SMART health are shown | M9 | Not started |
| AT-F06-02 | Mount management | Mount/unmount data disks to allow-listed mount roots; persistent via systemd mount units | M9 | Not started |
| AT-F06-03 | Format | Format a non-system disk (ext4, xfs, btrfs) with typed confirmation; system disk is never offered | M9 | Not started |
| AT-F06-04 | Usage alerts | Threshold alerts for capacity and SMART failures | M15 | Not started |

## F07 — Web-based file manager

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F07-01 | Browse | Browse within configured roots only; path traversal and symlink escapes are rejected | M10 | Not started |
| AT-F07-02 | Transfer | Upload (resumable, size-limited) and download (streamed) | M10 | Not started |
| AT-F07-03 | Operations | Create folder, rename, move, copy, delete-to-trash, restore from trash | M10 | Not started |
| AT-F07-04 | Permissions | Per-role root access; operations audited | M10 | Not started |
| AT-F07-05 | Preview | Text and image preview; served with `Content-Disposition: attachment` and sandbox CSP for untrusted content | M10 | Not started |

## F08 — Secure user and session management

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F08-01 | First-run owner setup | Owner account created via one-time setup token printed to the journal; token single-use and expiring | M2 | Done (CI 40510127374; merge pending owner review) |
| AT-F08-02 | Password auth | Argon2id hashing; breached/weak password rejection; rate limiting and lockout with backoff | M2 | Done (CI 40510127374; merge pending owner review) |
| AT-F08-03 | Sessions | Server-side sessions, secure/HttpOnly/SameSite cookies, idle and absolute timeouts, rotation on privilege change | M2 | Done (CI 40510127374; merge pending owner review) |
| AT-F08-04 | CSRF | All state-changing requests require a valid CSRF token and same-origin check | M2 | Done (CI 40510127374; merge pending owner review) |
| AT-F08-05 | Session management UI | Users see and revoke their sessions; Owners revoke any session | M5 | Done (CI 40519204275; merge pending owner review) |
| AT-F08-06 | User lifecycle | Create, disable, delete users; Owner cannot delete the last Owner | M2 | Done (CI 40510127374; merge pending owner review) |

## F09 — Passkeys, MFA and role-based access control

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F09-01 | RBAC | Every API route declares a permission; a test enumerates all routes and fails if any route lacks one | M2 | Done (CI 40510127374; merge pending owner review) |
| AT-F09-02 | Passkeys | WebAuthn registration and login; passkey-only accounts supported | M11 | Not started |
| AT-F09-03 | TOTP | TOTP enrolment with recovery codes; replay of a used code is rejected | M11 | Not started |
| AT-F09-04 | Step-up auth | Destructive and security-relevant actions require recent re-authentication | M11 | Not started |
| AT-F09-05 | MFA policy | Owner can require MFA for roles; policy downgrades are audited and need step-up | M11 | Not started |

## F10 — Security dashboard and audit logging

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F10-01 | Audit log | Every authentication event and state change is recorded with actor, action, target, result and request ID | M2 | Done (CI 40510127374; merge pending owner review) |
| AT-F10-02 | Tamper evidence | Audit records are hash-chained; verification detects modified or deleted records | M2 | Done (CI 40510127374; merge pending owner review) |
| AT-F10-03 | Audit UI | Filter, search and export (JSON Lines) | M17 | Not started |
| AT-F10-04 | Security dashboard | Shows MFA coverage, exposed apps, policy exceptions, outdated images, failed logins, certificate expiry | M17 | Not started |

## F11 — Network and reverse proxy management

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F11-01 | Routes | Create, edit, delete Caddy routes for apps (hostname and path based) | M12 | Not started |
| AT-F11-02 | Access control | Per-route options: Kernhaven SSO gate, IP allow-list, LAN-only | M12 | Not started |
| AT-F11-03 | Safe apply | Config is validated by Caddy before apply; failed apply keeps the previous config | M12 | Not started |
| AT-F11-04 | Network overview | Interfaces, addresses, listening ports and Docker networks shown read-only | M12 | Not started |

## F12 — TLS certificate management

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F12-01 | ACME | Automatic certificates via ACME (HTTP-01 and DNS-01 for supported providers) | M13 | Not started |
| AT-F12-02 | Internal CA | LAN-only hosts use a local CA; root certificate downloadable for client trust | M13 | Not started |
| AT-F12-03 | Custom certificates | Upload certificate and key; validated (chain, key match, expiry) before use | M13 | Not started |
| AT-F12-04 | Expiry monitoring | Expiry warnings at 30/14/3 days | M15 | Not started |

## F13 — System and container monitoring

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F13-01 | Host metrics | CPU, memory, load, disk I/O, network, temperatures where available | M14 | Not started |
| AT-F13-02 | Container metrics | Per-container CPU, memory, network, block I/O | M14 | Not started |
| AT-F13-03 | History | 7-day retention with downsampling; bounded storage | M14 | Not started |
| AT-F13-04 | Service health | Core, agent, Docker and Caddy health on the dashboard | M14 | Not started |

## F14 — Encrypted, scheduled backup and restore

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F14-01 | Encryption | Backups encrypted client-side with an authenticated cipher; key never stored unencrypted on the backup target | M16 | Not started |
| AT-F14-02 | Targets | Local disk, SFTP and S3-compatible targets | M16 | Not started |
| AT-F14-03 | Scope | Platform config, database, app data volumes; consistent snapshots (app quiesce or DB-native dump) | M16 | Not started |
| AT-F14-04 | Scheduling and retention | Cron-like schedules; retention policies; missed runs caught up after downtime | M16 | Not started |
| AT-F14-05 | Restore | Full platform restore onto a fresh Debian 13 host and per-app restore; restore verified by app health checks | M16 | Not started |
| AT-F14-06 | Integrity | Periodic verification detects corrupted or tampered backups | M16 | Not started |

## F15 — Reliable platform upgrades and rollback

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F15-01 | Signed releases | Release artifacts are signed; unsigned or mismatched artifacts are refused | M18 | Not started |
| AT-F15-02 | Upgrade | In-place upgrade with automatic pre-upgrade DB snapshot | M18 | Not started |
| AT-F15-03 | Rollback | Failed post-upgrade health check rolls back binaries and DB automatically; manual rollback available | M18 | Not started |
| AT-F15-04 | Upgrade path test | Upgrade from N-1 to N with real data passes on both architectures | M18 | Not started |

## F16 — Notifications and operational alerts

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F16-01 | Channels | E-mail (SMTP), webhook, ntfy, Gotify | M15 | Not started |
| AT-F16-02 | Rules | Alert rules for health, resources, certificates, backups, security events | M15 | Not started |
| AT-F16-03 | Delivery | Retries with backoff, deduplication, rate limiting, delivery log | M15 | Not started |

## F17 — Safe installation and uninstall

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F17-01 | Installer | `.deb` packages for amd64 and arm64 plus a verified install script; pre-flight checks (OS, arch, systemd, Docker, ports, disk) | M18 | Not started |
| AT-F17-02 | Idempotency | Re-running the installer is safe and repairs a partial install | M18 | Not started |
| AT-F17-03 | Uninstall | Uninstall removes services, users and units; data removal is opt-in; apps keep running unless removal is requested | M18 | Not started |
| AT-F17-04 | No host side effects | Installer does not change firewall, SSH config or unrelated packages | M18 | Not started |

## F18 — Crash recovery and persistent background jobs

| ID | Capability | Acceptance criterion | MS | Status |
|---|---|---|---|---|
| AT-F18-01 | Persistent job queue | Jobs survive restarts; at-least-once execution with idempotent steps | M3 | Done (CI 40511595535; merge pending owner review) |
| AT-F18-02 | Crash recovery | `kill -9` of Core or agent at any job step recovers to a consistent state on restart | M3 | Done (CI 40511595535; merge pending owner review) |
| AT-F18-03 | Job visibility | Users see job progress, logs and outcome; jobs can be cancelled where safe | M5 | Done (CI 40519204275; merge pending owner review) |
| AT-F18-04 | Power-loss safety | SQLite WAL with synchronous=FULL for journal tables; recovery after simulated power loss (VM reset) | M3 | Blocked (B-2: VM reset test); WAL + synchronous=FULL in place |
