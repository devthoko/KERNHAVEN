# M18 — Installer, Upgrades, Rollback, Signed Releases

Status: Implemented and verified on Ubuntu 24.04 (CI 40967427295); Debian 13 run pending B-2; release key pending B-3; merge pending owner review
Depends on: M16 (backups), all services' units
Acceptance tests: AT-F15-01 … AT-F15-04, AT-F17-01 … AT-F17-04
Threats addressed: TH-43, TH-45 (below)

## Pieces

| Piece | Where |
|---|---|
| Release verification (minisign) | `internal/release`, ADR-0013 |
| Upgrader (snapshot, health check, automatic and manual rollback) | `internal/upgrade`, `cmd/kernhaven-upgrade`, ADR-0032 |
| Package | `scripts/package.sh`, `packaging/debian/{postinst,prerm,postrm}` |
| Installer / uninstaller | `packaging/install.sh`, `packaging/uninstall.sh` |
| Grant key creation for the package | `kernhaven-core init-keys` |
| Lifecycle test on real hosts | `scripts/package-test.sh`, CI job `package` (amd64, arm64) |

## Procedures

**Install:** `apt-get install minisign`, then as root
`./install.sh --pubkey owner.pub RELEASE_DIR`. Set `public_origin` in
`/etc/kernhaven/core.toml`; the setup token is in
`journalctl -u kernhaven-core`.

**Upgrade:** `kernhaven-upgrade verify DIR`, then `kernhaven-upgrade apply
DIR`. Exit code 3 means the new version failed and the previous one runs
again with its database. `kernhaven-upgrade rollback` returns to the version
before the last upgrade (changes since are lost); `status` shows the history.
Take a backup (M16) before upgrading; the upgrade snapshot covers the
database and its key, not the apps' volumes.

**Remove:** `/usr/share/kernhaven/uninstall.sh` (apps and data stay),
`--remove-apps`, `--remove-data`.

## Threats

| ID | Threat | Mitigation |
|---|---|---|
| TH-43 | A tampered release or upgrade | minisign-signed checksums with an offline key; pinned keys on the host; verification before any change; packages checked against the signed hash |
| TH-45 | The installer weakens the host | No changes to firewall, SSH or unrelated packages (checked before/after in CI); services created with their documented sandboxing; configuration written only where missing |

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F15-01 | `TestMinisignFormat` (key and signature format; untrusted key, other key with the same ID, changed message, changed trusted comment, malformed input); `TestRelease` (swapped package, changed checksum list, unsigned, no trusted key); `TestUntrustedReleaseChangesNothing`; CI: the real minisign's signatures verify with `kernhaven-upgrade verify`; unsigned and tampered releases refused on a real installation |
| AT-F15-02 | `TestUpgradeSucceeds` (snapshot before the package, versions recorded, same and older versions need an explicit decision); CI: N-1 → N on a real installation with users and a migration |
| AT-F15-03 | `TestFailedUpgradeRollsBack` (database and package back, broken package not cached), `TestUpgradeSucceeds` (manual rollback with the earlier database), `TestUpgradeNeedsCachedPackage`; CI: a release whose Core never becomes ready is rolled back (exit 3), then a manual rollback to N-1 |
| AT-F15-04 | CI job `package` on amd64 and arm64: N-1 is the M15 commit (migrations up to 0013), N this branch; the users created under N-1 sign in after the upgrade and after both rollbacks |
| AT-F17-01 | CI: `install.sh` with pre-flight checks installs the package and every service runs |
| AT-F17-02 | CI: a second run repairs a deleted grant key and a stopped agent and keeps the administrator's configuration |
| AT-F17-03 | CI: removal stops and removes units, users and configuration, keeps a running app and the data; a reinstall uses the kept data; `--remove-data` deletes it |
| AT-F17-04 | CI: SSH configuration, firewall rules and the package list (except Kernhaven) are identical before and after install, repair, upgrades and rollbacks |

## Known limitations

- **No release key exists yet (B-3).** Until the owner's key is created and
  added to `deploy/release-keys/`, packages ship without a trusted key and
  every upgrade is refused; CI uses a throwaway key.
- **Verified on Ubuntu 24.04 runners, not on Debian 13 (B-2).** The
  installer refuses Ubuntu unless `--allow-unsupported`; the same test must
  pass on Debian 13 VMs before a release (M19).
- Upgrades are command-line only (no upgrade from the web interface).
- The upgrade snapshot covers the database and its key; apps' volumes are
  covered by backups (M16), not by the upgrade.
- Caddy and Docker come from the distribution; the installer does not
  install or configure them.

## Verification evidence (2026-10-29, branch `m18-installer`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` | `khv01-dev` | Passed |
| CI full suite (all jobs incl. Debian 13 userland, real Docker, E2E) | GitHub Actions | Passed (run 40967427295) |
| `internal/release`, `internal/upgrade` unit tests | `khv01-dev` | Passed |
| `scripts/package.sh` builds a package (contents and control fields checked) | `khv01-dev` | Passed — the first build had a 0700 root directory and group-writable directories (umask); fixed |
| Our minisign verification against signatures made by the real minisign 0.11 | GitHub Actions (amd64, arm64) | Passed |
| Package lifecycle on real hosts (install, repair, upgrade, failed upgrade, rollbacks, removal, host side effects) | GitHub Actions (Ubuntu 24.04, amd64 and arm64) | Passed (run 40967427295) — on the way the job found: (1) `/etc/kernhaven` was 0750 root:kernhaven (enforced by the Core unit's `ConfigurationDirectoryMode`), so the agent and the monitor could not read their configuration and did not start — now 0755 with `core.toml` 0640; (2) the comparison of the host state counted firewall packet counters — rules only now; plus test-script fixes (password policy, error reporting) |
| Flaky `TestAgentStatusAvailable` on Debian/arm64: a kept-alive connection to a restarted agent failed the next call | `khv01-dev`, GitHub Actions | Fixed — the Core opens one agent connection per call |
