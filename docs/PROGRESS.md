# Kernhaven 1.0 — Progress Checkpoint

Last updated: 2026-10-27. This file is the resumption point for development
sessions. It states only verified facts; see the linked evidence.

## Overall status

**Kernhaven 1.0 is not complete.** 2 of 20 milestones are done (M0, M1). M2 is implemented with green CI on
branch `m2-identity` and awaits owner review; M3 is implemented on branch
`m3-jobs` (based on M2). No user-facing
product exists yet: there is no web UI, no host agent, no Docker, storage,
network, backup or installer functionality.

| MS | Name | State | Evidence |
|---|---|---|---|
| M0 | Spec, repo, CI | Done | `main` @ `f0d2c71` |
| M1 | Core foundation | Done | [M1 evidence](milestones/M1-core-foundation.md#verification-evidence-2026-10-27), CI run 40506636168 |
| M2 | Identity, sessions, RBAC, audit | Implemented, CI green (run 40510127374); owner review pending | [M2 evidence](milestones/M2-identity.md#verification-evidence-2026-10-27-branch-m2-identity) |
| M3 | Persistent jobs, crash recovery | Implemented, CI green (run 40511595535); owner review pending | [M3 evidence](milestones/M3-jobs.md#verification-evidence-2026-10-27-branch-m3-jobs) |
| M5 | Web dashboard shell | Implemented on branch `m5-dashboard` (based on M3); CI pending | [M5 design](milestones/M5-dashboard.md) |
| M4, M6–M19 | see [milestones](milestones/MILESTONES.md) | Not started | — |

## Environment blockers

| ID | Blocker | Blocks | Needed from owner |
|---|---|---|---|
| B-1 | Docker Engine missing on `khv01-dev`; installing needs `sudo` | M4, M6–M8, M14, M16 integration | Install Docker Engine (and add a dedicated test user/VM policy) |
| B-2 | No disposable Debian 13 VMs (amd64, arm64) | All privileged integration, upgrade, backup/restore and release tests (G3/G4) | Provide VMs or a hypervisor the dev server may use |
| B-3 | Release signing key ceremony undecided (ADR-0013) | M18, signed artifacts | Decision + offline key |
| B-5 | Playwright browsers need system libraries on the dev server (`sudo`) | Local E2E runs | None — E2E runs in CI; optional `sudo npx playwright install-deps chromium` |
| B-6 | No C toolchain on the dev server | Local `-race` runs | None — CI covers it; optional `sudo apt install gcc` |

## Next steps (in order)

1. Owner reviews and merges `m2-identity`, then `m3-jobs`.
2. Owner reviews `m5-dashboard`.
3. M4 onward requires B-1 (Docker), then B-2 (Debian 13 VMs) for release evidence.

## Development environment

- Dev server `khv01-dev` (Ubuntu 26.04, amd64), user `dev01`, repo `~/KERNHAVEN`.
- Go 1.27.3 in `~/.local/go`, Node.js 24.22.1 LTS in `~/.local/node` (checksum-verified downloads).
- Push via deploy key `~/.ssh/kernhaven_deploy` (host alias `github-kernhaven`).
- Run `scripts/check.sh` before every commit.
