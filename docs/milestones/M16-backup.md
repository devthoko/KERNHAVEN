# M16 — Encrypted Backup and Restore

Status: Implemented (CI 40949090854); merge pending owner review
Depends on: M3, M6, M8, M9, M15
Acceptance tests: AT-F14-01 … AT-F14-06
Threats addressed: TH-50, TH-55, TH-56, TH-57 (below), TH-51 (secret key in backups)

## Model

- A **repository** is a target (local directory, SMB share folder, SFTP directory, S3 bucket)
  holding encrypted snapshots (ADR-0029). It is created with a passphrase
  that Kernhaven never stores, or connected to with it.
- A **plan** says what is backed up (the platform, all or some stacks), to
  which repository, when (cron), and what is kept (retention).
- A **snapshot** is one run: the platform (database, secret key, `core.toml`
  for reference) and the named volumes of each stack.

## What is backed up (AT-F14-03)

| Part | How | Consistency |
|---|---|---|
| Database | `VACUUM INTO` a temporary file | SQLite transaction snapshot while the Core runs |
| Secret key (`secrets.key`) | file | needed to decrypt stack secrets after a restore (ADR-0019) |
| `core.toml` | file | for reference; host-specific, not applied by a restore |
| Stack volumes | `volumes.export` through the Docker agent (ADR-0030) | the stack is stopped while its volumes are copied (default; can be switched off per plan) and started again |

Not included: the agent's grant key and the units (host-specific, created by
the installer), bind-mounted host directories, container images (pulled
again), Caddy's state (generated from the database).

## Schedules and retention (AT-F14-04)

- Five-field cron expressions in the host's time zone and `@hourly`,
  `@daily`, `@weekly`, `@monthly`; at most four runs an hour.
- The scheduler checks every 30 s. A run that was due while the Core was
  down is made once on start (marked `catch-up`), not once per missed slot.
- Retention per plan: keep the last N, one per day/week/month for N
  days/weeks/months; the newest snapshot is always kept. Incomplete
  snapshots (no manifest) older than 24 h are removed.
- Each repository is verified on its own schedule (weekly by default).

## Restore (AT-F14-05)

**One stack** (UI or API, `backup.manage` + step-up): the stack is stopped,
its current volumes copied to `<volume>.pre-restore`, the volumes replaced
from the snapshot, the stack started and its containers waited for until
running and healthy. If any step fails, the previous data is copied back
and the stack started again.

**The whole platform on a new host** (offline, before the first start):

1. Install Kernhaven; do not start `kernhaven-core` (or stop it).
2. Write a target file, for example `/root/target.json` (mode 0600):
   `{"kind":"local","config":{"path":"/mnt/usb/kernhaven"}}`, or for SFTP
   with `"secret":{"password":"…"}` or `"private_key_file":"…"`, or for S3
   with `"secret":{"secret_access_key":"…"}`, or for an SMB share
   `{"kind":"smb","config":{"host":"nas","share":"backup","path":"kernhaven","user":"kh"},"secret":{"password":"…"}}`.
   Local paths must be inside
   `backup.local_roots`.
3. As the Core's user: `kernhaven-core restore -config /etc/kernhaven/core.toml
   -target /root/target.json [-snapshot ID] [-passphrase-file F]`
   (`-list` shows the snapshots). Every object is verified first; the
   database and the secret key are written, the old ones kept as
   `*.before-restore-<time>`; all sessions are signed out and unfinished
   jobs of the old host cancelled. The command refuses to run while the Core
   holds the data directory, and refuses to replace an installation with
   users unless `-replace` is given.
4. Start `kernhaven-core`. A `backup.restore_platform` job recreates each
   stack's volumes, imports their data and redeploys the stack; the job
   succeeds when every stack's deployment passed its health checks.

## API

| Route | Permission |
|---|---|
| `GET /backup/repositories`, `GET /backup/plans`, `GET /backup/repositories/{id}/snapshots[/{snapshot}]` | `backup.read` (owner, admin, operator) |
| `POST /backup/plans/{id}/run`, `POST /backup/repositories/{id}/verify` | `backup.run` (owner, admin, operator) |
| `POST/PUT/DELETE /backup/repositories…`, `POST …/snapshots/{snapshot}/restore` | `backup.manage` (owner, admin) + step-up |
| `POST/PUT/DELETE /backup/plans…`, `GET /backup/sftp-key`, `POST /backup/sftp-scan` | `backup.manage` |

## Threats

| ID | Threat | Mitigation |
|---|---|---|
| TH-50 | Theft of backups | Authenticated encryption on the host; key wrapped with Argon2id(passphrase); no names in object paths |
| TH-55 | A damaged or tampered backup is restored | Every segment authenticated before use; manifest bound to repository and snapshot; restores keep the current data until the stack is healthy; periodic verification |
| TH-56 | A compromised Core uses backups to read or overwrite other data | The agent exports and imports only volumes labelled for the named stack, never snapshot copies or unmanaged volumes; archives are filtered (no `..`, absolute names, links escaping, devices) |
| TH-57 | SSRF or credential theft through targets | Address guard (ADR-0028) for SFTP, S3 and SMB; SMB signing required (ADR-0036); SFTP host keys pinned after the administrator compared the fingerprint; credentials sealed and write-only; step-up |

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F14-01 | `TestStreamRoundTrip` (all segment boundaries), `TestRepoHeader` (passphrase length, wrong passphrase, ID bound to the key, bounded KDF parameters, no key or passphrase in the file); `TestBackupAndRestoreThroughCore` (no plaintext of volume, database or secrets anywhere on the target; data key stored sealed); E2E |
| AT-F14-02 | `TestLocalTarget` (roots, symbolic links, `os.Root`, no temporary files left); `TestSFTPTarget` (in-process SSH server: Core key and password, host key scan and pinning, wrong host key refused before authentication, guard); `TestSignV4` (AWS examples), `TestS3Target` (multipart flow, prefix, guard, invalid settings); `TestS3RealServer` (real S3 server in CI); `TestSMBTargetSettings` and `TestSMBRealServer` (Samba in CI, ADR-0036); refusal of name escapes on every target |
| AT-F14-03 | `TestBackupAndRestoreThroughCore` (platform + stack volumes, stack stopped and started again); `TestM16VolumeExportImport` (real Docker: owners, modes, hard and symbolic links, FIFO, dot files, times, 3 MB file, old content replaced; other stacks' volumes and escaping archives refused); `TestFilterTar` |
| AT-F14-04 | `TestSchedule` (cron fields, ranges, steps, day-of-month/weekday OR, leap day, limits), `TestRetention`; `TestBackupSchedule` (one catch-up run after three missed nights, verification scheduled); retention through the API (only the last two kept, on the target too) |
| AT-F14-05 | `TestBackupAndRestoreThroughCore` (one stack restored and healthy; a restore from a damaged snapshot fails and puts the previous data back); `TestPlatformRestore` (empty data directory and empty Docker: wrong passphrase refused, listing, database and secret key restored, sessions removed, second restore refused, stacks' volumes imported and redeployed, the owner signs in); `TestRestoreCommand` (lock against a running Core both ways, input errors) |
| AT-F14-06 | `TestStreamTamper` (bit flips in data, tag and salt, truncation at and inside segments, reordering, appended data, other object, other key, mixed objects); `TestRepoObjects` (hash and identity mismatches, moved manifest); `TestBackupAndRestoreThroughCore` (verification passes, then reports a flipped byte and a deleted snapshot, audited) ; E2E |

## Known limitations

- Full copies only: no deduplication, compression or incremental backups.
- Consistency of databases inside apps relies on stopping the stack; there
  are no application-specific dumps.
- Only named volumes; bind mounts of host directories are not included.
- Extended attributes and ACLs inside volumes are not preserved.
- Restoring one stack requires the stack to exist on the host; a deleted
  stack comes back only through a platform restore.
- There is no UI for the platform restore; it is a command run on the host.
- A full restore onto a *fresh Debian 13 host* is verified with an empty
  data directory and an empty Docker in tests; the run on a real Debian 13
  VM is part of the M19 release verification (VMs not yet available, B-2).
- Snapshots cannot be deleted by hand in the UI (only by retention).

## Verification evidence (2026-10-29, branch `m16-backup`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck incl. `pkg/sftp`, builds) | `khv01-dev` | Passed |
| `internal/core/backup` unit tests | `khv01-dev` | Passed — signatures match AWS's published examples |
| `TestS3RealServer` against `rclone serve s3` (pinned image) | `khv01-dev` | Passed (signatures, three-part multipart upload, verified snapshot, wrong secret refused) |
| `TestM16VolumeExportImport` on real rootless Docker 29.9.2 | `khv01-dev` | Passed — the first run found that `copyUIDGID` gives every file to the helper's user; it is no longer sent |
| `TestBackupAndRestoreThroughCore`, `TestBackupSchedule`, `TestPlatformRestore`, `TestRestoreCommand`, contract, RBAC | `khv01-dev` | Passed — the first run found that deployed stacks have the status `deployed`, not `running` (restores would not restart them) |
| Mutation checks: last-segment flag ignored, paths below symbolic links allowed, device files allowed, no copy-back after a failed restore, local roots not enforced, host key not pinned, missing snapshots not reported, newest snapshot not protected — each makes a test fail. Removing the manifest's snapshot-ID check leaves the per-snapshot key derivation, which still rejects a moved manifest (defence in depth) | `khv01-dev` | Passed |
| CI full suite: unit tests on amd64/arm64 and Debian 13, real Docker export/import and the real S3 server (`rclone serve s3`) on amd64/arm64, browser E2E (repository, plan, backup, snapshot, check, axe) | GitHub Actions | Passed (run 40949090854) |
