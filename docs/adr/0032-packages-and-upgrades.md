# ADR-0032: Debian packages, an idempotent installer and a CLI upgrader with automatic rollback

- Status: Accepted
- Date: 2026-10-29

## Context
F15 and F17 need installation, repair, upgrades with rollback and removal
on Debian 13 (amd64, arm64). The Core runs unprivileged and must not be able
to replace binaries; host security settings must not change.

## Decision
- **Package:** one `kernhaven` `.deb` per architecture with the binaries,
  the units, configuration examples, the trusted release keys, `install.sh`
  and `uninstall.sh`. `postinst` is idempotent: it creates the service users
  and directories, writes configuration only where none exists (with the
  Core's UID), creates the grant key as the Core's user and copies its
  public half to a root-owned path, enables and restarts the units (the
  Docker agent only with Docker, the proxy and Caddy only with Caddy). It
  never touches the firewall, SSH or other packages.
- **Installer:** `install.sh` checks the platform (Debian 13; others only
  with `--allow-unsupported`), architecture, systemd, ports, disk space and
  Docker, verifies the signed release (ADR-0013) and installs the package
  with apt (dependencies only). Running it again repairs.
- **One-line install:** `packaging/get.sh`, fetched from the repository,
  pins the owner's release key, downloads the GitHub release, verifies it
  and runs its `install.sh`.
- **Upgrades:** `kernhaven-upgrade` runs as root from the command line; the
  web interface cannot start it. It verifies the release, stops the Core,
  copies the database and the secret key, installs the package and waits
  for the Core to report the new version and become ready. If it does not,
  it reinstalls the previous package (kept from the last install or
  upgrade) and puts the snapshot back. `rollback` returns to the version
  before the last upgrade with the database of that moment.
- **Removal:** `uninstall.sh` purges the package (services, units,
  configuration, users); data is deleted and apps removed only when asked
  (`--remove-data`, `--remove-apps`); containers keep running otherwise.

## Consequences
- Rolling back restores the database of the upgrade moment: changes made
  under the new version are lost (stated in the CLI and the docs).
- An installation that was not made by `install.sh` has no cached package;
  the upgrader refuses until `install.sh` ran once.
- Upgrades from the web interface would need a privileged update service;
  that is not part of 1.0.
