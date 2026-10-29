# Kernhaven User Guide

What each page does and who may use it. Roles: **Owner** (everything),
**Admin** (everything except owner management and policy downgrades),
**Operator** (start/stop, logs, trigger backups), **Viewer** (read only).

| Page | What you do there | Roles |
|---|---|---|
| Dashboard | Health of the platform, running apps, active jobs and alerts — updated live | all |
| Monitoring | Host and container metrics for 1 hour to 7 days | Operator+ |
| Alerts | Current and past alerts; channels (e-mail, webhook, ntfy, Gotify); rules | read: Operator+, change: Admin+ |
| Backups | Repositories, plans, snapshots, restores | read and run: Operator+, change and restore: Admin+ |
| Security | Findings: missing second factors, open routes, exceptions, outdated apps, failed sign-ins, certificates, audit chain, backups | Admin+ |
| Apps / App store | Install, update (with data snapshot and rollback), remove apps from signed catalogs | read: Viewer+, change: Admin+ |
| Stacks | Compose stacks with revisions, variables (secrets write-only), deployments | read: Viewer+, change: Admin+ |
| Containers / Images / Volumes / Networks | Docker objects; logs follow live; a console for admins | read: Viewer+, operate: Operator+, console and change: Admin+ |
| Storage | Disks, SMART, formatting and mounts | read: Operator+, change: Admin+ |
| Files | File manager with uploads, previews, trash | per role and root |
| Reverse proxy / Certificates | Publish apps with Kernhaven sign-in, LAN-only or address lists; TLS per host | read: Operator+, change: Admin+ |
| Jobs | Background work with its steps and log | Viewer+ |
| Users | Accounts and roles | Admin+ |
| Audit log | Search, filter, export (JSON Lines), verify | Admin+ |
| Account | Password, passkeys, authenticator app, recovery codes, sessions, theme | all |

## Good habits

- Add a passkey or an authenticator app; owners and admins without one are
  flagged as critical on the Security page.
- Some actions ask you to confirm it is you (step-up) — changing where data
  goes, restores, consoles, removing apps.
- Prefer LAN-only routes; publish to the internet only with Kernhaven
  sign-in.
- Keep the backup passphrase outside the server.

## The console

Containers → a container → Console (admins, after confirming it is you):
a shell in the container as its user. Type a command and press Enter;
full-screen programs do not work. Opening and closing are audited, what you
type is not.
