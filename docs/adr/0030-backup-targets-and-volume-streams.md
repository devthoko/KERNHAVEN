# ADR-0030: Backup targets and volume contents streamed through the Docker agent

- Status: Accepted
- Date: 2026-10-29

## Context
AT-F14-02 needs local disks, SFTP and S3-compatible storage; AT-F14-03 needs
the data of app volumes. The Core runs unprivileged and never touches the
Docker socket (ADR-0005); volumes live wherever Docker keeps them.

## Decision
- **Volumes:** the Docker agent gets two stream operations. `volumes.export`
  creates a helper container (pinned busybox, never started, no network,
  read-only, the volume mounted read-only) and returns a tar of the volume
  through Docker's archive API. `volumes.import` empties the volume with a
  fixed script in a helper and extracts a tar into it. Both accept only
  volumes labelled as belonging to the named stack (not snapshot copies).
  The agent re-writes every archive in both directions and accepts only
  regular files, directories, symbolic links, hard links to earlier files
  and FIFOs below `data/`; `..`, absolute names, paths below an earlier
  symbolic link and device files are refused; extended attributes are
  dropped. Owners, modes and times are kept. Stacks are stopped while their
  volumes are copied (configurable) and started again afterwards.
- **Local:** a directory below `backup.local_roots` in `core.toml`, given
  without symbolic links; all access goes through `os.Root`.
- **SFTP:** `github.com/pkg/sftp` v1.13.11 over `golang.org/x/crypto/ssh`.
  The server's host key must be scanned, shown as a SHA-256 fingerprint and
  saved before use; connections pin it. Authentication by a password or by
  the Core's own Ed25519 key, whose public key the UI shows.
- **S3:** a small client of our own (Signature V4, single and multipart
  uploads, ListObjectsV2), tested against AWS's published signature
  examples and a real server (`rclone serve s3`) in CI.
- Remote targets dial through the address guard of ADR-0028 (no loopback,
  link-local or multicast; no redirects).

## Consequences
- One new dependency (`pkg/sftp`, plus `kr/fs`), vetted by govulncheck.
- Restoring requires the stack's containers to be stopped; a restore keeps
  the current data in `<volume>.pre-restore` until the stack is healthy.
- Docker extracts the archive itself; the agent's filter is a second line
  of defence behind Docker's own confinement to the helper's file system.
- Bind-mounted host directories are not backed up (only named volumes); this
  is documented for users.
