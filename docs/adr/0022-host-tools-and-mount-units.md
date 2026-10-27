# ADR-0022: Fixed host tools for storage and systemd mount units

- Status: Accepted
- Date: 2026-10-27

## Context
Disk inventory, partitioning, file system creation and persistent mounts
(M9) need either kernel interfaces reimplemented in Go (sysfs parsing, GPT
writing, mkfs) or the standard Linux tools. `/etc/fstab` edits are a common
source of unbootable systems. CLAUDE.md forbids executing shell commands from
API input.

## Decision
The agent executes a fixed set of programs (`lsblk`, `smartctl`, `sfdisk`,
`mkfs.ext4|xfs|btrfs`, `udevadm`, `systemctl`) resolved once at startup from
`/usr/sbin:/usr/bin:/sbin:/bin`, with argument vectors it builds itself from
validated, typed parameters, never through a shell, with `LC_ALL=C`, a
minimal environment and timeouts. Output is parsed from JSON where the tool
offers it. Persistent mounts are systemd `.mount` units under
`/etc/systemd/system`, referencing devices by UUID, with `nofail,nosuid,nodev`,
marked `X-Kernhaven-Managed=yes`; Kernhaven never edits `/etc/fstab`.

## Consequences
- Behaviour depends on tool versions; parsers are tested with recorded output
  of several util-linux versions and tolerate numbers encoded as strings.
- Missing optional tools reduce features (no SMART, fewer file systems)
  instead of failing.
- Mount units are visible and manageable with standard systemd tools; a
  missing disk does not block boot.
- These operations need root, so they run in a separate storage service (the
  agent binary with `role = "storage"`, its own systemd unit and socket) that
  offers nothing else. The Docker agent keeps its unprivileged sandbox; a
  compromise of one service does not grant the other's capabilities.
