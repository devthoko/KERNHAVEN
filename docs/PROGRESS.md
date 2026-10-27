# Kernhaven 1.0 — Progress Checkpoint

Last updated: 2026-10-27. This file is the resumption point for development
sessions. It states only verified facts; see the linked evidence.

## Overall status

**Kernhaven 1.0 is not complete.** 2 of 20 milestones are done (M0, M1); M2 is
implemented on branch `m2-identity` and awaits CI and review. No user-facing
product exists yet: there is no web UI, no host agent, no Docker, storage,
network, backup or installer functionality.

| MS | Name | State | Evidence |
|---|---|---|---|
| M0 | Spec, repo, CI | Done | `main` @ `f0d2c71` |
| M1 | Core foundation | Done | [M1 evidence](milestones/M1-core-foundation.md#verification-evidence-2026-10-27), CI run 40506636168 |
| M2 | Identity, sessions, RBAC, audit | Implemented, local checks pass; CI + review pending | [M2 evidence](milestones/M2-identity.md#verification-evidence-2026-10-27-branch-m2-identity) |
| M3 | Persistent jobs, crash recovery | Next | — |
| M4–M19 | see [milestones](milestones/MILESTONES.md) | Not started | — |

## Environment blockers

| ID | Blocker | Blocks | Needed from owner |
|---|---|---|---|
| B-1 | Docker Engine missing on `khv01-dev`; installing needs `sudo` | M4, M6–M8, M14, M16 integration | Install Docker Engine (and add a dedicated test user/VM policy) |
| B-2 | No disposable Debian 13 VMs (amd64, arm64) | All privileged integration, upgrade, backup/restore and release tests (G3/G4) | Provide VMs or a hypervisor the dev server may use |
| B-3 | Release signing key ceremony undecided (ADR-0013) | M18, signed artifacts | Decision + offline key |
| B-4 | Pushing security-sensitive changes needs the owner's authorization (directive) | CI evidence (race detector, arm64, Debian 13) for M2+ | Approve pushing `m2-identity` and review/merge |
| B-5 | No Node.js on the dev server (needed to build the web UI) | M5 | None — can be installed in the user's home without `sudo` |
| B-6 | No C toolchain on the dev server | Local `-race` runs | None — CI covers it; optional `sudo apt install gcc` |

## Next steps (in order)

1. Push `m2-identity`, get CI green, review, merge; then mark M2 rows Done.
2. M3: persistent job queue with step journal and crash recovery (no host
   privileges needed; can proceed without B-1/B-2).
3. M5: web dashboard shell (install Node.js in `~/.local`).
4. M4 onward requires B-1, then B-2 for release evidence.

## Development environment

- Dev server `khv01-dev` (Ubuntu 26.04, amd64), user `dev01`, repo `~/KERNHAVEN`.
- Go 1.27.3 in `~/.local/go` (checksum-verified download from go.dev).
- Push via deploy key `~/.ssh/kernhaven_deploy` (host alias `github-kernhaven`).
- Run `scripts/check.sh` before every commit.
