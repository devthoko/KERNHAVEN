# ADR-0023: File access through os.Root in the storage service, streamed

- Status: Accepted
- Date: 2026-10-28

## Context
The file manager (M10) reads and writes data owned by many users below the
mount root. String-based path checks are a classic source of traversal and
symlink escapes (TH-31). The agent protocol (M4) carries JSON only, with a
16 MiB response limit and a 6-minute deadline.

## Decision
File operations run in the root storage service (M9). Each operation opens
its configured root with `os.Root` (Go standard library; on Linux it resolves
paths with `openat2(RESOLVE_BENEATH)`), so escapes through `..` or symlinks
fail in the kernel; validation of relative paths happens in addition, not
instead. Large data moves through a second endpoint, `POST /v1/stream/{op}`,
whose grant and parameters are carried in headers and verified exactly like
JSON operations; only the storage role offers stream operations. Copies and
emptying the trash are journaled Core jobs.

## Consequences
- The Core never opens data files; a Core compromise is limited to what the
  storage service's typed operations allow inside the roots.
- Symlinks inside a root are followed; that is acceptable because they cannot
  leave the root.
- Rename uses an existence check before renaming; a file created in the same
  instant by another process could be replaced. This cannot cross a root.
