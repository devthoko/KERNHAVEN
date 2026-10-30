# Kernhaven Operator Guide

For whoever installs and runs Kernhaven on a host. Version 1.0 (release
candidate documentation; see [the 1.0 gate](../release/1.0-GATE.md) for what
is still open).

## 1. Requirements

| Item | Requirement |
|---|---|
| OS | Debian 13 (trixie), amd64 or arm64, systemd |
| Docker | Docker Engine from Debian (`docker.io`) or Docker's repository; rootful or rootless |
| Reverse proxy | Caddy 2.6+ from Debian (`caddy`); its own `caddy.service` stays disabled |
| Disk | 2 GiB free in `/var/lib` plus space for apps and backups |
| Ports | 80 and 443 for Caddy; 8470 on loopback for the Core |
| Tools | `minisign` to verify releases |

Kernhaven never changes the firewall or SSH configuration. Decide yourself
which ports your router forwards.

## 2. Install

One line (downloads the latest signed release from GitHub, verifies it
against the key pinned in the script, then runs its `install.sh`):

    apt-get install caddy docker.io
    curl -fsSL https://raw.githubusercontent.com/devthoko/KERNHAVEN/main/packaging/get.sh | sudo bash

Settings: `KERNHAVEN_VERSION=1.0.0` (a given version),
`KERNHAVEN_ALLOW_UNSUPPORTED=1` (a development host other than Debian 13),
`KERNHAVEN_RELEASE_URL` (a mirror; the signature check still applies).
`minisign` is installed if missing. Without a release key the script refuses.

From a downloaded release directory instead:

    apt-get install minisign caddy docker.io
    ./install.sh --pubkey owner.pub RELEASE_DIR

`install.sh` checks the host, verifies the release signature and installs
the package. It creates the users `kernhaven`, `kernhaven-agent`,
`kernhaven-proxy`, `kernhaven-monitor`, the directories `/etc/kernhaven`,
`/var/lib/kernhaven`, `/var/lib/kernhaven-backups`,
`/var/lib/kernhaven-upgrade`, and starts the services (the Docker agent only
with Docker, the proxy and Caddy only with Caddy).

Then:

1. Set `public_origin` in `/etc/kernhaven/core.toml` to the address users
   type (for example `https://kernhaven.home.arpa`) and
   `systemctl restart kernhaven-core`.
2. Read the one-time setup token: `journalctl -u kernhaven-core | grep setup_token`.
3. Open the address, enter the token and create the owner account; add a
   passkey or an authenticator app right away (Account page).

Running `install.sh` again repairs a damaged installation (users,
directories, keys, units) and never replaces existing configuration.

## 3. Services

| Unit | User | Purpose |
|---|---|---|
| `kernhaven-core` | kernhaven | Web UI and API (loopback only), jobs, database |
| `kernhaven-agent` | kernhaven-agent (+docker) | The only component with Docker access |
| `kernhaven-storage` | root | Disks, formatting, mounts (allow-listed operations) |
| `kernhaven-files` | root | File manager below the mount root |
| `kernhaven-proxy` | kernhaven-proxy | The only client of Caddy's admin socket |
| `kernhaven-monitor` | kernhaven-monitor | Host metrics from /proc and /sys |
| `kernhaven-caddy` | caddy | Caddy with Kernhaven's configuration |

All units are sandboxed (`systemd-analyze security` ≤ 2.0, checked in CI).
Logs: `journalctl -u <unit>`.

## 4. Configuration

`/etc/kernhaven/core.toml` (Core) and one file per service. Unknown keys are
refused at startup. Important settings:

- `server.public_origin` — the browser-facing address (CSRF, cookies).
- `containers.allowed_bind_roots` — host paths containers may mount.
- `backup.local_roots` — directories for local backup repositories.
- `files.roots.*` — narrow roles per file root.

## 5. Backups and disaster recovery

Configure a repository and a plan on the Backups page (owner or admin).
**Write down the repository passphrase**; without it no backup can be
restored on another host. Scheduled verification runs weekly.

Restore one app: Backups → Snapshots → Restore. Restore everything on a new
host: install Kernhaven, do not open the UI, then as the `kernhaven` user:

    kernhaven-core restore -config /etc/kernhaven/core.toml -target target.json [-snapshot ID]

and start `kernhaven-core`; it brings the apps back. Details:
[M16](../milestones/M16-backup.md#restore-at-f14-05).

## 6. Upgrades and rollback

    kernhaven-upgrade verify RELEASE_DIR
    kernhaven-upgrade apply RELEASE_DIR

The upgrader stops the Core, keeps a copy of the database and its key,
installs the package and waits for the new version. If it does not become
ready, the previous version and database come back (exit code 3).
`kernhaven-upgrade rollback` returns to the version before the last upgrade
with the database of that moment (later changes are lost);
`kernhaven-upgrade status` shows the history. Take a backup before
upgrading: apps' volumes are not part of the upgrade snapshot.

## 7. Audit log

Security dashboard and Audit log pages (owner, admin). Export the log as
JSON Lines regularly and keep the files elsewhere; on any machine,

    kernhaven-core audit-check new.jsonl old.jsonl

shows whether the log was truncated or rewritten between two exports.

## 8. Removal

    /usr/share/kernhaven/uninstall.sh               # services, users, configuration
    /usr/share/kernhaven/uninstall.sh --remove-apps # also Kernhaven's containers and volumes
    /usr/share/kernhaven/uninstall.sh --remove-data # also /var/lib/kernhaven*

Without options, apps keep running and data stays.

## 9. Troubleshooting

| Symptom | Look at |
|---|---|
| UI unreachable | `systemctl status kernhaven-core kernhaven-caddy`; `public_origin`; ports 80/443 |
| "agent unavailable" | `systemctl status kernhaven-agent`; Docker running; `/etc/kernhaven/agent-grant.pub` present (re-run `install.sh`) |
| Upgrade refused "no release key" | add the owner's minisign key to `/etc/kernhaven/release-keys/` |
| Job failed | Jobs page shows the step journal and log |
| Alerts not delivered | Alerts page → delivery log |
