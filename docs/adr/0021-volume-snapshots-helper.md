# ADR-0021: Volume snapshots with an agent-built helper container

- Status: Accepted
- Date: 2026-10-27

## Context
Updating an app can change the data in its volumes (database migrations). A
rollback that only restores containers would start the old version on data
it may not understand (AT-F05-02). Docker has no volume snapshot API, and the
host's storage may not support file system snapshots.

## Decision
Before an app update the deploy job copies every volume of the stack to a
snapshot volume, and copies it back during compensation. Copies run in a
helper container that the agent constructs from fixed settings: a busybox
image pinned by digest, a fixed command, no network, read-only root file
system, `no-new-privileges`, only the capabilities needed to preserve
ownership, the source mounted read-only. The new agent operation
`volumes.copy` accepts only volume names and requires both volumes to belong
to the same stack. It returns immediately; the Core polls the helper.

## Consequences
- Updates need free disk space for one copy of the app's data and take longer
  for large volumes; copies are file-level, not atomic snapshots, which is why
  the containers are removed first.
- The helper runs as root inside the container; with rootless Docker that is
  the unprivileged host user, with rootful Docker it is confined to the two
  mounted volumes without network.
- The helper image must be pullable or present once; air-gapped hosts set
  `helper_image` to a local image.
