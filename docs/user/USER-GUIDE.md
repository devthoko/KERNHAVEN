# Kernhaven User Guide

What each page does and who may use it. Roles: **Owner** (everything),
**Admin** (everything except owner management and policy downgrades),
**Operator** (start/stop, logs, trigger backups), **Viewer** (read only).

Home shows your apps, the state of the server and what needs a look. The
sidebar groups the pages into areas, and pages of one area are tabs at the
top (for example Docker → Containers, Stacks, Images, Volumes, Networks).

The top bar is on every page: press Ctrl+K (⌘K on a Mac) or click the
search field to jump to any page, app or action; the bell lists what needs
attention; your picture opens the account menu with settings, theme and
sign-out.

| Area → page | What you do there | Roles |
|---|---|---|
| Home | Your apps as tiles (open or manage), processor, memory, storage and network at a glance, what needs attention, recent activity — updated live | all |
| Apps → Installed / App store / Catalog sources | Install, update (with data snapshot and rollback), remove apps from the built-in Kernhaven Essentials and from signed catalogs you add; turn sources off | read: Viewer+, install: Admin+, sources: Owner |
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
| Account (account menu in the top bar) | Password, passkeys, authenticator app, recovery codes, sessions, theme | all |

## Kernhaven Essentials

The app store starts with eleven hand-picked apps that come with Kernhaven:
Vaultwarden (passwords), Jellyfin, Navidrome and Audiobookshelf (media),
Syncthing (file sync), Uptime Kuma (monitoring), Forgejo (Git), Stirling PDF,
Mealie (recipes), Home Assistant and FreshRSS. Their images are pinned and
none needs a policy exception. They are updated with Kernhaven; owners can
turn the list off under Apps → Catalog sources.

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
