# M6 — Container Management

Status: In progress
Depends on: M4 (agent), M5 (UI), M3 (jobs)
Acceptance tests: AT-F02-01 … AT-F02-06; AT-F02-07 and AT-F01-05 are split
into M6b (see "Scope split")
Threats addressed: TH-21, TH-30, TH-31 (bind mounts), TH-33, TH-41

## Goal

Manage the containers, images, volumes and networks of the host's Docker
Engine from the UI and API, through the agent only, with a container policy
that rejects dangerous configurations by default and makes every exception
explicit, owner-approved and audited.

## Scope split

| Item | Where | Reason |
|---|---|---|
| AT-F02-01..06 | M6 | This document |
| AT-F02-07 interactive exec console | M6b | Needs bidirectional streaming through the agent (WebSocket ↔ unix socket ↔ Docker attach) with its own threat analysis |
| AT-F01-05 server-sent live status | M6b | Shares the streaming design with exec; M6 refreshes by polling (2 s) |
| Live log follow | M6 by polling with `since`; streaming in M6b | Same |
| Container resource usage | M14 | Monitoring milestone |

## Container policy (`internal/policy`)

The policy evaluates a Kernhaven `ContainerSpec` (a typed subset of Docker's
create options; anything not representable cannot be requested). It is
evaluated **twice**: in the Core before asking the agent, and again in the
agent before calling Docker (defense in depth).

**Violations** (block creation unless an exception covers the rule):

| Rule | Condition |
|---|---|
| `privileged` | privileged mode |
| `host-network`, `host-pid`, `host-ipc`, `host-uts` | host namespaces |
| `capability` | any added capability |
| `device` | any host device |
| `security-opt` | seccomp/apparmor/selinux unconfined or `no-new-privileges=false` |
| `bind-mount` | bind mount whose source is not below an allowed bind root |
| `docker-socket` | mounting the Docker socket — **never exemptible** |
| `sensitive-path` | bind source `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/boot`, `/root`, `/run`, `/var/run`, `/var/lib/docker`, `/var/lib/kernhaven` or below — **never exemptible** |

**Warnings** (shown, not blocking): image not pinned by digest, port
published on all interfaces, port below 1024, runs as root, no memory
limit, restart policy `always`.

**Exceptions:** only owners may approve an exception, per container and per
rule, with a written reason. The approval is part of the create request,
recorded in the audit log (`policy.exception`), shown as a label on the
container (`io.kernhaven.policy.exceptions`) and listed on the container
page. The agent re-evaluates the policy and accepts only exceptions for
exemptible rules. Residual risk: a fully compromised Core could forge an
exception; closing this needs exception signing with a key outside the Core
(planned with step-up authentication in M11, tracked as TH-21).

## Agent operations (added to the pinned allow-list)

`containers.create`, `containers.remove`, `containers.pause`,
`containers.unpause`, `containers.logs`, `images.list`, `images.pull`,
`images.remove`, `images.prune`, `volumes.list`, `volumes.create`,
`volumes.remove`, `networks.list`, `networks.create`, `networks.remove`.

- `containers.logs`: `tail` 1–10000, optional `since`/`until` (Unix
  seconds), timestamps; stdout/stderr demultiplexed; response capped at 2 MiB.
- `images.pull`: reference validated; result includes the resolved digest
  (digest pinning, TH-41). Long-running, so the Core runs it as a job.
- Removal of in-use volumes/networks/images returns `conflict` from Docker
  and is reported as such (AT-F02-06).
- Networks are created as `bridge`; `internal` optional; no host or macvlan
  drivers.

## Core API (permissions)

| Permission | Owner | Admin | Operator | Viewer |
|---|---|---|---|---|
| `containers.read` | ✓ | ✓ | ✓ | ✓ |
| `containers.operate` (start/stop/restart/pause/unpause, logs) | ✓ | ✓ | ✓ | |
| `containers.manage` (create/remove; images, volumes, networks) | ✓ | ✓ | | |
| `policy.exceptions` | ✓ | | | |

Endpoints under `/api/v1/containers`, `/api/v1/images`, `/api/v1/volumes`,
`/api/v1/networks`, plus `POST /api/v1/containers/validate` (policy preview).
Every state change is audited with actor, target and outcome. Image pulls run
as job `images.pull` (deduplicated per reference).

Logs require `containers.operate` because they frequently contain secrets.

## UI

Containers list (state, image, ports, actions), container detail (summary,
security-relevant settings, policy exceptions, logs with tail/time range and
auto-refresh), create form with live policy evaluation, images (pull, remove,
prune), volumes and networks (create, remove).

## Acceptance criteria → tests

| AT | Tests |
|---|---|
| AT-F02-01 | Agent integration: list/inspect containers, images, volumes, networks on real Docker; UI e2e on CI Docker |
| AT-F02-02 | Lifecycle incl. pause/unpause/remove through Core API with audit records; e2e start/stop |
| AT-F02-03 | Logs with tail and since on a container that prints known lines (integration); UI shows them (e2e) |
| AT-F02-04 | Policy unit tests per rule; Core rejects with explanation; agent rejects even when Core is bypassed; owner exception accepted and audited; non-owner exception rejected; never-exemptible rules stay blocked |
| AT-F02-05 | Pull job resolves digest; list; remove; prune (integration) |
| AT-F02-06 | Create/remove volume and network; removing an in-use volume/network → conflict (integration) |
| AT-F09-01 | RBAC matrix and OpenAPI contract cover all new routes |

## Verification evidence (2026-10-27, branch `m6-containers`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed |
| Policy unit tests: safe spec, 18 violation cases, symlink escape, prefix trick, exceptions (partial, superfluous, never-exemptible), warnings, 22 malformed specs, image references | `khv01-dev` | Passed |
| Agent tests: pinned allow-list of 22 operations; agent rejects privileged/host network/Docker socket/`/etc` even with exceptions; labels `managed`, `created_by`, `policy.exceptions`; 11 parameter validation cases | `khv01-dev` | Passed |
| Core tests through a real agent server: lifecycle with audit, policy and owner-only exceptions (admin refused, short reason refused, Docker socket never), pull job with digest and no retry on not-found, volumes/networks with conflict mapping, behaviour without agent | `khv01-dev` | Passed |
| Contract: 46 operations; routes ↔ OpenAPI; documented `x-permission` equals enforced permission; RBAC matrix | `khv01-dev` | Passed |
| Integration on real rootless Docker 29.9.2: pull resolves digest; missing image fails; agent refuses privileged; create with volume + internal network + digest-pinned image + start; labels; stdout/stderr logs and `since`; pause/unpause; in-use volume/network conflict; remove (conflict without force); prune; built-in network protected | `khv01-dev` | Passed, no leftovers |
| Live UI check in a browser against real rootless Docker: create with live policy panel, running as 65534, "created by owner", log line visible, stop (exit 137 after grace period), remove with typed confirmation | `khv01-dev` | Passed; badge layout defect found and fixed |
| CI incl. browser E2E with the runner's Docker (pull, create with policy panel, logs, stop/start, volumes, networks, remove, axe, layouts) | GitHub Actions | Pending |
