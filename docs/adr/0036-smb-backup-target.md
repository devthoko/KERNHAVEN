# ADR-0036: SMB file shares as backup targets

- Status: Proposed (pending owner review)
- Date: 2026-10-30
- Extends: ADR-0030

## Context
Most homelabs already have a NAS or a Windows share. Backups to it were
only possible through SFTP (often disabled on NAS devices) or by mounting
the share on the host and using a local target, which needs root, host
packages and an fstab entry outside Kernhaven's control.

## Decision
- **The Core speaks SMB itself**, like SFTP and S3: no host mount, no root,
  no host package. Connections go through the address guard (ADR-0028).
- **Library:** `github.com/cloudsoda/go-smb2`, pinned to commit 95daac2ef783
  (BSD-2-Clause, maintained fork of `hirochachacha/go-smb2`). The original
  v1.1.0 (2022) rejects the unsigned STATUS_PENDING interim responses that
  Samba sends for slow writes when signing is required, so it cannot be used
  with required signing; the fork skips verification exactly where MS-SMB2
  3.2.5.1.3 says so and verifies everything else. Cost: it pulls in
  `gokrb5` for Kerberos support, which Kernhaven does not use yet.
- **Security settings:** SMB 2.0.2 to 3.1.1 only (no SMB 1), message
  signing required, NTLMv2 with a user and password (domain optional). The
  password is sealed with the Core's key and write-only in the API, as for
  SFTP. Confidentiality does not rely on SMB encryption: every object is
  already encrypted by the repository format (ADR-0029); signing protects
  against changes and session hijacking on the network.
- **Settings:** host, port (445), share name, an optional folder inside the
  share (must exist; Kernhaven does not create the repository root), user,
  domain. Share and folder names are validated; object names are the same
  closed set as for the other targets.
- **Writes** go to a temporary name and are renamed after a successful
  flush and close; SMB does not replace on rename, so the repository file
  is removed first when it is replaced (as for SFTP servers without
  posix-rename).
- **Schema:** migration 0016 allows `smb` in `backup_repos.kind`. SQLite
  cannot change a CHECK constraint, so the repository, plan and snapshot
  tables are rebuilt with all rows and ids; a test upgrades a version-15
  database with data and checks the foreign keys.
- **Tests:** unit tests for settings, guard and failure handling; an
  integration test against Samba 4.23 (container pinned by digest, CI and
  dev server) runs every target operation and a verified snapshot, and
  checks that a wrong password and a missing share are refused.

## Consequences
- Backups to a NAS need only a share and an account; the offline restore
  (`kernhaven-core restore`) reads SMB targets from the same target file.
- No Kerberos and no SMB host identity pinning: SMB has no host key; the
  signed NTLMv2 session proves that the server knows the account's password.
- A pseudo-version dependency must be reviewed on every update; govulncheck
  covers it in CI.
