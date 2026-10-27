# M9 — Storage and Disk Management

Status: Implemented (CI 40601258272); merge pending owner review
Depends on: M4, M5
Acceptance tests: AT-F06-01 … AT-F06-03 (AT-F06-04 alerts follow in M15)
Threats addressed: TH-32 (formatting or unmounting the system disk), TH-31
(mount paths), TH-22 (agent operations stay typed)

## Goal

See every disk with its partitions, file systems, usage and SMART health;
mount data disks persistently below an allow-listed root; format a disk that
is provably not in use. Destructive actions are impossible on the system disk,
need a typed confirmation and the user's password, and are journaled.

## Where the work happens: a separate storage service

Disk operations need root (raw block devices, `/etc/systemd/system`). The
Docker agent of M4 deliberately has none: it runs as `kernhaven-agent` with no
capabilities, a read-only system and `PrivateDevices=yes`. Giving it root
would weaken the existing boundary for every Docker operation. M9 therefore
adds a **second privilege domain**: the same binary in the role `storage`
(`deploy/systemd/kernhaven-storage.service`, config `storage.toml`):

| | Docker agent (`role = "docker"`) | Storage service (`role = "storage"`) |
|---|---|---|
| User | `kernhaven-agent` + `docker` group | `root`, capabilities `SYS_ADMIN`, `SYS_RAWIO` only |
| Operations | containers, images, volumes, networks | `agent.info`, `storage.inventory`, `storage.format`, `storage.mount`, `storage.unmount` — nothing else |
| Writable | nothing | `/etc/systemd/system`, the mount root |
| Network | none | none |
| Socket | `/run/kernhaven/agent.sock` | `/run/kernhaven-storage/storage.sock` |

Both verify the Core's signed grants and the peer UID; both allow-lists are
pinned by tests, and each role rejects the other's operations. The Core never
runs host tools (`internal/core/storage` only authorizes, confirms, audits and
journals). The storage service runs a fixed set of programs (ADR-0022), each with
an absolute path resolved at startup from `/usr/sbin:/usr/bin:/sbin:/bin`,
argument vectors built by the agent (no shell), `LC_ALL=C`, a minimal
environment and a timeout:

| Tool | Used for | Required |
|---|---|---|
| `lsblk --json --bytes` | inventory | yes (util-linux) |
| `smartctl --json` | SMART health per disk | optional; inventory says "SMART unavailable" |
| `sfdisk` | new GPT with one Linux partition | for formatting |
| `mkfs.ext4`, `mkfs.xfs`, `mkfs.btrfs` | file systems | each optional; only installed ones are offered |
| `udevadm settle` | wait for the new partition | for formatting |
| `systemctl` | mount units | for mounting |

## Classification (the safety core)

The storage service classifies every device from the `lsblk` tree on **every** request —
the Core's view is never trusted for a destructive decision:

| Class | Rule | Offered actions |
|---|---|---|
| System disk | any device in its tree is mounted at `/`, `/boot`, `/boot/efi`, `/usr`, `/var`, `/home`, `/opt`, `/srv` (outside the mount root), `/etc` or is swap | none |
| In use | any device in its tree is mounted outside the Kernhaven mount root, or is a member of LVM, RAID, dm-crypt or multipath | none (reason shown) |
| Managed | file systems mounted by a Kernhaven mount unit below the mount root | unmount |
| Free disk | `type=disk`, writable, nothing mounted, no holders | format |
| Free file system | an unmounted ext4, xfs, btrfs, vfat or exfat file system on a non-system disk | mount |

Read-only devices, optical drives, zram and loop devices are never offered
(loop devices only with the test-only agent setting `storage_include_loop`).

## Format (AT-F06-03)

Request: device path, the disk's identity as the user saw it (serial or WWN
and size), file system, label, typed confirmation (the device name) and the
user's password. The Core checks confirmation and password (audited
re-authentication, as in M8), then runs a journaled job that is never retried
automatically. The storage service re-reads
the inventory, refuses unless the device is still a free disk **with the same
identity and size** (a disk swapped between page load and confirmation is not
formatted), then:

1. `sfdisk --wipe always --wipe-partitions always <disk>` with the script
   `label: gpt` / `type=linux` (one partition over the whole disk);
2. `udevadm settle`, find the new partition in a fresh `lsblk`;
3. `mkfs.<fs>` with forced overwrite and the label;
4. return partition path and UUID.

Labels: `^[A-Za-z0-9_-]{1,12}$` (the xfs limit). There is no compensation —
formatting cannot be undone; the job fails visibly at the step that failed.

## Mounts (AT-F06-02)

Mount points are `<mount_root>/<name>` with `name` `^[a-z0-9][a-z0-9-]{0,30}$`
and `mount_root` from the agent configuration (default `/srv/kernhaven`, must
be absolute, clean and not `/`). Mounting writes
`/etc/systemd/system/<escaped path>.mount`:

```ini
# Managed by Kernhaven. Remove it on the storage page.
[Unit]
Description=Kernhaven data disk <name>
X-Kernhaven-Managed=yes

[Mount]
What=/dev/disk/by-uuid/<uuid>
Where=<mount_root>/<name>
Type=<fstype>
Options=nofail,nosuid,nodev

[Install]
WantedBy=multi-user.target
```

then `systemctl daemon-reload` and `systemctl enable --now`. The device is
referenced by UUID so it survives renaming (`sdb` → `sdc`); `nofail` keeps the
host booting when the disk is missing; `nosuid,nodev` stop a foreign disk from
bringing setuid programs or device nodes. Unmounting (`disable --now`, remove
the unit, `daemon-reload`) only touches units with the `X-Kernhaven-Managed`
marker below the mount root; a busy file system is reported, not forced.
Unit file names use systemd's path escaping (`-` becomes `\x2d`).

To use a mounted disk in containers, add the mount root to the containers'
`allowed_bind_roots` (M6); otherwise bind mounts below it need an exception.

## API

| Route | Permission |
|---|---|
| `GET /api/v1/storage` | `storage.read` (owner, admin, operator) |
| `POST /api/v1/storage/mounts`, `DELETE /api/v1/storage/mounts/{name}` | `storage.manage` (owner, admin) |
| `POST /api/v1/storage/format` | `storage.manage` + password + typed confirmation |

## Privileges

Formatting and mounting need the storage service to run as root (its systemd
unit). Started as an ordinary user (development, the browser tests in CI), it
reports the inventory and refuses every change with "needs the agent to run
as root"; the storage page then says so instead of offering actions.

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F06-01 | `internal/agent/storage`: parsing of recorded `lsblk` output (this dev server, NVMe+SATA with LVM, RAID member, USB disk, old util-linux with string numbers), SMART parsing (passed, failed, unsupported); Core `TestStorageInventory`; E2E storage page |
| AT-F06-02 | unit file content and escaping (compared with `systemd-escape`), `systemctl` calls, rollback of a failed mount, busy unmount keeps the unit, refusal of foreign units and names; Core `TestStorageMounts`; CI job `storage`: mount through systemd, write to the disk, unit enabled, busy unmount refused, unmount |
| AT-F06-03 | 11 refusals in `TestFormatRefusals` (system disk, LVM member, mounted elsewhere, Kernhaven mount, swapped serial, changed size, unknown device, path traversal, bad label, missing or unknown mkfs) before any tool runs; Core `TestStorageFormat` (confirmation, password, system disk refused by the service, audit, operator forbidden); CI job `storage`: the runner's real system disk refused, loop device formatted with ext4, xfs and btrfs under the real unit's sandbox |

## Known limitations

- Formatting always creates one GPT partition over the whole disk; existing
  partitions cannot be formatted individually, and there is no resizing,
  RAID, LVM, encryption or multi-disk btrfs/ZFS management.
- Mountable file systems: ext4, xfs, btrfs, vfat, exfat (exfat and vfat need
  kernel support). NTFS is not offered.
- A disk with any file system mounted outside the mount root is "in use" as a
  whole, even if another partition on it is free.
- SMART needs `smartmontools` and root; virtual disks and many USB bridges do
  not report SMART. Capacity and SMART alerts follow in M15 (AT-F06-04).
- The storage service's unit was checked with `systemd-analyze` (exposure 1.9,
  threshold 2.0) and exercised as root on a CI runner; Debian 13 VMs (B-2) are
  still needed for release evidence. On the development server it runs only
  without root (inventory).
- Re-authentication for formatting uses the password; passkey step-up follows
  in M11.

## Verification evidence (2026-10-28, branch `m9-storage`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed |
| `internal/agent/storage`: classification of recorded `lsblk` output (this server, a homelab with NVMe/SATA/LVM/RAID/USB/read-only/zram/optical, util-linux < 2.37), SMART parsing, unit name escaping compared with the real `systemd-escape`, format command sequence, 11 refusals before any tool runs, mount unit content, rollback, busy unmount, foreign units untouched | `khv01-dev` | Passed |
| Agent allow-lists: Docker role unchanged, storage role exactly `agent.info` + 4 storage operations | `khv01-dev` | Passed |
| Core through a real server in the storage role (`TestStorageInventory`, `TestStorageFormat`, `TestStorageMounts`), contract (75 operations), RBAC | `khv01-dev` | Passed (3 consecutive runs) |
| Mutation check: disabling system-disk detection makes 5 tests fail | `khv01-dev` | Passed |
| Live: Core + storage service (without root) on this server — `sda` with `/` classified as system disk, usage shown, SMART "not installed", no actions offered; storage page at 375 px without horizontal overflow | `khv01-dev` | Passed |
| CI job `storage`: real unit as root under systemd, loop device: system disk refused, ext4/xfs/btrfs formatted, mounted via systemd, written, busy unmount refused, unmounted | GitHub Actions | Passed (run 40601258272) |
| CI full suite incl. browser E2E (storage page with the runner's disks, viewer without access) | GitHub Actions | Passed (run 40601258272) |
