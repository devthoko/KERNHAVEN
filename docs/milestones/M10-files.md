# M10 — Web-Based File Manager

Status: Implemented (CI 40701148605); merge pending owner review
Depends on: M9
Acceptance tests: AT-F07-01 … AT-F07-05
Threats addressed: TH-31 (path traversal, symlink escapes), TH-04 (XSS through
file content), TH-06 (large bodies), TH-09 (authorization per route and root)

## Goal

Browse, upload, download, preview and organise files in the data folders of
the homelab — below the mount root of M9 — from the browser, without giving
the internet-facing Core access to the file system.

## Where files are touched

Files under the mount root belong to many users (apps write as their own
UIDs), so file operations need root. They run in a **file service** of their
own: the agent binary with `role = "files"` (`deploy/systemd/kernhaven-files.service`,
`files.toml`), root with only `CAP_CHOWN`, `CAP_DAC_OVERRIDE`,
`CAP_DAC_READ_SEARCH` and `CAP_FOWNER`, no network, no device access,
writable only below the mount root. It is a third privilege domain next to
the Docker agent and the disk service of M9: the file service cannot mount or
format, the disk service cannot read files, the Docker agent can do neither.
The Core authorizes, audits, keeps upload sessions and streams data through;
it never opens a data file itself.

A first version ran the file operations inside the disk service. The CI job
that runs the real unit as root found that the disk service's capabilities
do not allow writing into folders of other users, and adding them would have
raised its systemd exposure above the CI threshold (2.2 > 2.0). Splitting
the roles keeps both below it (disk service 1.9, file service 1.5) and is the
better least-privilege design.

### File roots

The file service configuration names the roots (`[[file_roots]]`, each
`name` and `path`); every path must lie at or below `mount_root`. Without
configuration there is one root, `data` = `mount_root`. The Core only ever
sends root **names** and relative paths; it cannot point the service at
another directory.

### Path confinement (ADR-0023)

Every operation opens its root with Go's `os.Root` (Linux: `openat2` with
`RESOLVE_BENEATH`) and resolves the relative path inside it. `..`, absolute
paths and symlinks that lead outside the root fail in the kernel, not in a
string check. Before that, paths are validated (relative, clean, no NUL, at
most 4096 bytes, names at most 255 bytes) and names starting with
`.kernhaven-` are reserved (trash and upload staging live there and are never
listed or addressed directly). Symlinks inside a root are shown as links and
followed only within the root.

New files and folders get the owner and group of the folder they are created
in, so apps keep access to files uploaded for them.

### Streaming (ADR-0023)

The agent protocol gains `POST /v1/stream/{op}`: the signed grant and the
parameters travel in headers (the grant binds operation and parameter hash
exactly as before), the body carries upload data or the response carries the
file. Only the files role offers stream operations (`files.read`,
`files.upload.append`). Per-request deadlines are extended for these
requests only.

## Operations (AT-F07-03)

| Operation | Behaviour |
|---|---|
| list | entries with type, size, modification time, mode, owner; at most 10 000 per folder |
| create folder | fails if it exists |
| rename / move | within one root; never overwrites |
| copy | within or between roots, recursive, never overwrites; symlinks are skipped and reported; journaled job |
| delete | moves into `<root>/.kernhaven-trash/<id>/` with a record of the original path, time and user |
| restore | moves back; fails if something now exists at the original path; missing parent folders are created |
| empty trash | one item or all; journaled job |

## Transfers (AT-F07-02)

- **Upload** is resumable: the browser creates a session (root, target path,
  size; size ≤ `files.max_upload_bytes`, default 20 GiB), sends chunks of at
  most 8 MiB with their offset, can ask for the received size after an
  interruption and continue, then finishes. Data is staged in
  `<root>/.kernhaven-uploads/<session>.part` and renamed into place on finish;
  an existing file is never overwritten. Sessions expire after 24 hours; the
  Core removes expired sessions and their staged data.
- **Download** streams the file with `Content-Disposition: attachment`,
  `Content-Type: application/octet-stream`, `X-Content-Type-Options: nosniff`
  and `Content-Security-Policy: sandbox; default-src 'none'`.

The chunk route alone accepts bodies up to 8 MiB (all other routes keep
`max_body_bytes`), and transfer routes get longer read/write deadlines.

## Preview (AT-F07-05)

- **Text**: the first 256 KiB, returned as JSON only if it is valid UTF-8 and
  rendered by React as text (never as HTML).
- **Images**: PNG, JPEG, GIF and WebP, recognised by their content (not the
  file name), served with the exact image type, `attachment`, `nosniff` and
  the sandbox CSP — usable in `<img>`, harmless when opened directly. SVG and
  everything else are offered for download only.

## Permissions (AT-F07-04)

| Permission | Roles |
|---|---|
| `files.read` (browse, download, preview) | owner, admin, operator |
| `files.write` (upload, folders, rename, copy, delete, restore, empty trash) | owner, admin |

The Core configuration can restrict individual roots further
(`[files.roots.<name>] read = [...]`, `write = [...]`); lists only narrow
access, they never grant more than the permission. Every change and every
download is audited with root and path.

## API

| Route | Permission |
|---|---|
| `GET /api/v1/files/roots`, `GET /api/v1/files/list`, `GET /api/v1/files/download`, `GET /api/v1/files/preview`, `GET /api/v1/files/image`, `GET /api/v1/files/trash` | `files.read` |
| `POST /api/v1/files/mkdir`, `…/rename`, `…/copy`, `…/trash`, `…/trash/restore`, `…/trash/purge` | `files.write` |
| `POST /api/v1/files/uploads`, `GET/PUT/DELETE /api/v1/files/uploads/{id}`, `POST /api/v1/files/uploads/{id}/finish` | `files.write` |

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F07-01 | `internal/agent/files`: traversal (`..`, absolute, encoded, NUL), symlink to `/etc`, symlink chain leaving the root, reserved names, roots outside the mount root rejected; CI job with root on a mounted file system |
| AT-F07-02 | resumable upload (interrupted, resumed, wrong offset, too large, existing target), download headers and content |
| AT-F07-03 | create, rename, move, copy (incl. between roots), trash, restore, conflicts, empty trash |
| AT-F07-04 | RBAC matrix; per-root restriction; audit events |
| AT-F07-05 | text preview, binary refused, image sniffing (PNG served, SVG and HTML disguised as `.png` refused), headers |

## Known limitations

- Roots must lie at or below the mount root (the storage service's sandbox
  can write nowhere else). Data outside, for example Docker volumes under
  `/var/lib/docker`, is not reachable from the file manager.
- Symlinks inside a root are followed; symlinks that lead outside are refused.
  Copies skip symlinks and special files and report how many were skipped.
- Moving between different disks is refused (copy, then delete); the trash
  lives on the disk of each item, and the trash list covers the root and the
  disks mounted directly below it.
- Rename checks for an existing target before renaming (ADR-0023).
- No folder download as an archive, no in-browser editing, no search, no
  sharing links. Text previews show the first 256 KiB; images up to 50 MB.
- Upload sessions that expire are cleaned up when the next upload starts.
- Root-specific access lists come from the Core configuration, not the UI.

## Verification evidence (2026-10-28, branch `m10-files`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed |
| `internal/agent/files`: path validation, roots outside the mount root rejected, symlinks to `/etc`, to a file outside, relative and chained escapes, cross-root symlink, writing through a symlink, folder operations and conflicts, copy within/between roots (symlinks skipped, cancellation), trash/restore/purge, resumable uploads (wrong offset, oversized chunk rolled back, incomplete finish, existing target), byte ranges | `khv01-dev` | Passed |
| Mutation check: replacing `os.Root` with a plain `os.Open` makes the tests read `/etc/passwd` and a secret outside the root — they fail | `khv01-dev` | Passed |
| Agent allow-lists: a separate files role with exactly 11 file operations and 2 stream operations; the storage and Docker roles have none, the files role has no storage operation | `khv01-dev` | Passed |
| Core through a real storage-role server (`TestFilesPermissions`, `TestFilesConfinement`, `TestFilesDownloadAndPreview`, `TestFilesUpload`, `TestFilesOperations`), contract (92 operations), RBAC | `khv01-dev` | Passed (3 consecutive runs) |
| Mutation checks: ignoring per-root restrictions and dropping the sandbox CSP each make a test fail | `khv01-dev` | Passed |
| Live with real binaries: listing, symlink to `/etc` refused (422), download headers, 9 MiB upload in two chunks with a resume query arrives byte-identical; UI check (listing, text preview of HTML shown as text, wrapped actions, 375 px without horizontal overflow) | `khv01-dev` | Passed |
| CI job `storage`: file operations as root under the real `kernhaven-files` unit on an ext4 loop disk mounted by the real `kernhaven-storage` unit; neither service offers the other's operations (write into the propagated mount, owner inheritance 1000:1000, trash on the disk, restore, symlink to `/etc` refused for root) | GitHub Actions | Passed (run 40701148605) |
| First full CI run (40699924039) | GitHub Actions | Failed: (1) E2E cell selector matched two cells (test fixed); (2) the root job showed the disk service could not write into a disk folder owned by UID 1000 (missing DAC/CHOWN capabilities) — led to the separate file service |
| CI full suite incl. browser E2E (folder, upload, text preview, rename, trash, restore, axe; viewer without access) | GitHub Actions | Passed (run 40701148605) |
