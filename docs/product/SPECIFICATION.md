# Kernhaven Product Specification

**Name:** Kernhaven
**Tagline:** Your Server. Your Control.
**Status:** Draft v0.1 (M0)
**Target release:** 1.0 (production-ready, see [Quality Gates](../release/QUALITY-GATES.md))

## 1. Purpose

Kernhaven is a security-first, self-hosted management platform for a single
Linux server. It lets an advanced homelab user run applications in containers,
manage storage, files, networking, TLS, backups and upgrades from a web UI —
without handing the web application root access to the host.

Kernhaven is an independent, open-source alternative to CasaOS. It shares the
problem space, not code, design assets or branding.

## 2. Target users

| Persona | Description | Primary needs |
|---|---|---|
| Homelab owner | Runs one Debian server at home, comfortable with Linux | Install apps quickly, safe defaults, backups that work |
| Advanced operator | Writes own Compose files, runs a reverse proxy | Compose import, policy control, audit trail |
| Household member | Uses apps, not the platform | Limited, role-restricted access |

## 3. Product principles

1. **Host integrity first.** No web request can obtain root on the host.
2. **Deny by default.** Every API route, host operation and container
   capability is denied unless explicitly allowed.
3. **Real or not at all.** A feature is shipped only when it works end-to-end
   against real services with persistent data.
4. **Recoverable.** Every state-changing operation is journaled, resumable or
   safely abortable; backups are restorable and tested.
5. **Explainable.** Every security-relevant action is audited and visible.

## 4. Scope of version 1.0

The eighteen mandatory capabilities are listed with their sub-features,
milestones and acceptance tests in the [Feature Matrix](FEATURE-MATRIX.md):

1. Modern, responsive web dashboard
2. Complete Docker container management
3. Docker Compose import, validation, editing and deployment
4. Functional application store
5. App installation, updating and removal
6. Storage and disk management
7. Web-based file manager
8. Secure user and session management
9. Passkeys, MFA and role-based access control
10. Security dashboard and audit logging
11. Network and reverse proxy management
12. TLS certificate management
13. System and container monitoring
14. Encrypted, scheduled backup and restore
15. Reliable platform upgrades and rollback
16. Notifications and operational alerts
17. Safe installation and uninstall
18. Crash recovery and persistent background jobs

### Non-goals for 1.0

- Multi-node clusters, Kubernetes, Docker Swarm
- Hosts other than Linux; non-systemd init systems
- Running Kernhaven itself inside a container
- Public multi-tenant SaaS operation
- Managing the host firewall or SSH daemon configuration (explicitly excluded
  until a dedicated design is approved, see `CLAUDE.md`)

## 5. Supported platforms

| Tier | OS | Architectures | Meaning |
|---|---|---|---|
| Primary | Debian 13 (trixie) | amd64, arm64 | Release-blocking integration tests |
| Development | Ubuntu 26.04 LTS | amd64 | Developer machines; not release-blocking |

Runtime dependencies on the host: systemd, Docker Engine (from Debian or
Docker's apt repository), Caddy 2.

## 6. System overview

```
Browser ──HTTPS──▶ Caddy ──HTTP (loopback)──▶ kernhaven-core ──unix socket, authenticated──▶ kernhaven-agent ──▶ Docker Engine / systemd / disks / files
                                                   │
                                                 SQLite
```

- **kernhaven-core** — unprivileged Go service (own system user). Serves the
  API and the embedded web UI, holds the database, enforces authentication,
  authorization, policy and audit. Never talks to the Docker socket.
- **kernhaven-agent** — separate Go process with the minimum privileges needed
  for host operations. Accepts only typed, allow-listed operations that carry
  an authorization grant issued by the Core and verifies them independently.
- **Caddy** — TLS termination, reverse proxy for Kernhaven and installed apps.

Details: [Architecture](../architecture/ARCHITECTURE.md).

## 7. Roles

| Role | Capabilities (summary) |
|---|---|
| Owner | Everything, including user management, security policy, upgrades, restore |
| Admin | Apps, containers, storage, network, backups; no owner management, no policy downgrades |
| Operator | Start/stop/restart apps and containers, view logs and metrics, trigger backups |
| Viewer | Read-only dashboards |

Custom roles are out of scope for 1.0; permissions are fine-grained internally
so custom roles can be added later without schema changes.

## 8. Data and persistence

| Path | Content | Owner |
|---|---|---|
| `/etc/kernhaven/` | Configuration (`core.toml`, `agent.toml`) | root, readable by service user |
| `/var/lib/kernhaven/` | SQLite database, secrets, job journal | `kernhaven` user, mode 0700 |
| `/var/lib/kernhaven-agent/` | Agent state | agent user |
| journald | Service logs | systemd |

## 9. Quality attributes

| Attribute | 1.0 target |
|---|---|
| Security | OWASP ASVS 5.0 Level 2 verified; no critical/high open findings |
| Reliability | Recover from crash/power loss mid-operation without manual DB repair |
| Performance | Dashboard first load < 2 s on a Raspberry Pi 4 class arm64 board |
| Resource use | Core + agent idle RSS < 150 MB combined |
| Upgradability | Upgrade and rollback between any two consecutive releases |
| Accessibility | WCAG 2.2 AA for the dashboard |

## 10. Definition of "production-ready"

A capability is production-ready only when all of the following hold:

- It works end-to-end against real services (Docker Engine, Caddy, systemd,
  real block devices or loop devices in test) with persistent data.
- Its acceptance tests are automated and pass on the primary platforms.
- Its failure paths are tested, including interruption mid-operation.
- Its security requirements are verified and its threats are mitigated or
  explicitly accepted in the threat model.
- Its user and operator documentation is complete.

Simulated, mocked or stubbed behaviour is never reported as complete.
