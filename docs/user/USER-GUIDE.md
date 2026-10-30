# Kernhaven User Guide

What each page does and who may use it. Roles: **Owner** (everything),
**Admin** (everything except owner management and policy downgrades),
**Operator** (start/stop, logs, trigger backups), **Viewer** (read only).

The sidebar groups the pages into areas; pages of one area are tabs at the
top (for example Docker → Containers, Stacks, Images, Volumes, Networks).
Your account settings and sign-out are at the bottom of the sidebar.

| Area → page | What you do there | Roles |
|---|---|---|
| Home | Your apps as tiles (open or manage), processor, memory, storage and network at a glance, what needs attention, recent activity — updated live | all |
| Apps → Installed / App store / Catalog sources | Install, update (with data snapshot and rollback), remove apps from signed catalogs | read: Viewer+, change: Admin+ |
| Files | File manager with uploads, previews, trash | per role and root |
| Storage | Disks, SMART, formatting and mounts | read: Operator+, change: Admin+ |
| Backups | Repositories, plans, snapshots, restores | read and run: Operator+, change and restore: Admin+ |
| Monitoring → Overview | Host and container metrics for 1 hour to 7 days, services, platform versions | Operator+ |
| Monitoring → Alerts | Current and past alerts; channels (e-mail, webhook, ntfy, Gotify); rules | read: Operator+, change: Admin+ |
| Docker → Containers / Stacks / Images / Volumes / Networks | Docker objects and Compose stacks; logs follow live; a console for admins | read: Viewer+, operate: Operator+, console and change: Admin+ |
| Network → Reverse proxy / Certificates | Publish apps with Kernhaven sign-in, LAN-only or address lists; TLS per host | read: Operator+, change: Admin+ |
| Jobs | Background work with its steps and log | Viewer+ |
| Users | Accounts and roles | Admin+ |
| Security → Overview | Findings: missing second factors, open routes, exceptions, outdated apps, failed sign-ins, certificates, audit chain, backups | Admin+ |
| Security → Audit log | Search, filter, export (JSON Lines), verify | Admin+ |
| Account (gear in the user panel) | Password, passkeys, authenticator app, recovery codes, sessions, theme | all |

## Good habits

- Add a passkey or an authenticator app; owners and admins without one are
  flagged as critical on the Security page.
- Some actions ask you to confirm it is you (step-up) — changing where data
  goes, restores, consoles, removing apps.
- Prefer LAN-only routes; publish to the internet only with Kernhaven
  sign-in.
- Keep the backup passphrase outside the server.

## The console

Docker → Containers → a container → Console (admins, after confirming it is you):
a shell in the container as its user. Type a command and press Enter;
full-screen programs do not work. Opening and closing are audited, what you
type is not.
