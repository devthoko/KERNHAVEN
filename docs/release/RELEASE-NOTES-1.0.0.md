# Kernhaven 1.0.0 — release notes (DRAFT, not released)

This draft is prepared for the owner's review. Kernhaven 1.0.0 must not be
tagged or published until every box of the [1.0 gate](1.0-GATE.md) is
checked; several depend on decisions and infrastructure only the owner can
provide (Debian 13 VMs, the release signing key).

## What Kernhaven is

A self-hosting management platform for one Linux homelab server: a web UI
for containers, Compose stacks, an app store with signed catalogs, storage,
files, users with passkeys and MFA, a reverse proxy with TLS, monitoring,
alerts, encrypted backups and signed upgrades — without giving the web
application root access to the host.

## Highlights

- **Privilege separation:** the web application runs unprivileged on
  loopback; Docker, disks, files, Caddy and host metrics each sit behind
  their own sandboxed service with signed, allow-listed operations.
- **Apps:** Compose import with policy checks and audited exceptions;
  signed app catalogs; updates with a data snapshot and automatic rollback.
- **Accounts:** Argon2id passwords, passkeys, authenticator apps, recovery
  codes, MFA policy per role, step-up for sensitive actions.
- **Network and TLS:** routes with Kernhaven sign-in, LAN-only or address
  lists; ACME, DNS-01, internal CA or own certificates.
- **Operations:** host and container monitoring, alerts by e-mail, webhook,
  ntfy and Gotify, a security dashboard, a searchable, verifiable audit log.
- **Backups:** encrypted on the host (AES-256-GCM, Argon2id-wrapped key) to
  disks, SFTP or S3; schedules, retention, verification, per-app and full
  restore.
- **Live:** status changes without reloading, log follow, an audited console.
- **Install and upgrade:** Debian packages, a verified installer, upgrades
  with database snapshot and automatic rollback.

## Requirements

Debian 13 (amd64, arm64) with systemd; Docker Engine; Caddy 2.6+; minisign
for verification. See the [operator guide](../operations/OPERATIONS.md).

## Upgrade notes

First release: install with `install.sh`. Later releases:
`kernhaven-upgrade apply RELEASE_DIR`.

## Known limitations

Collected from the milestone documents; the most relevant:

- Upgrades only from the command line; the upgrade snapshot covers the
  database, apps' volumes are covered by backups.
- Full-copy backups (no deduplication or incremental backups).
- Line-based console (no TTY).
- No automatic forwarding of the audit log to a remote server.
- No vulnerability scanning of images.
