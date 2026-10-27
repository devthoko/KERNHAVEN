# M3 — Persistent Background Jobs and Crash Recovery

Status: In progress
Depends on: M1, M2 (API authorization)
Acceptance tests: AT-F18-01, AT-F18-02, AT-F18-04 (partial, see limitations)
Threats addressed: TH-53 (data consistency after crashes)

## Goal

Every long-running or multi-step operation of later milestones (container
deployment, app install/update, backups, upgrades) runs as a persistent job
whose progress survives crashes, restarts and power loss, and which either
completes or is rolled back as far as technically possible.

## Design (`internal/core/jobs`)

### Model

- A **job kind** is registered in code with a name, a payload validator that
  returns the ordered list of **steps**, and a retry limit. There is no API
  to create arbitrary jobs; modules enqueue their own kinds.
- A **step** has `Run` and an optional `Compensate`. Both must be idempotent:
  execution is at-least-once, because a crash can happen after a step's
  effect but before its completion is journaled.
- Steps can persist small JSON outputs that later steps (and compensations)
  read, e.g. "container ID created in step 2".

### Tables (migration `0004_jobs.sql`)

| Table | Content |
|---|---|
| `jobs` | kind, state, payload, attempts/max, lease owner and expiry, cancel flag, outcome, error, needs-attention flag, dedupe key, timestamps |
| `job_steps` | step journal: index, name, state (`pending`, `done`, `compensated`), outputs, timestamps |
| `job_logs` | bounded per-job log lines (max 500) |

A partial unique index on `dedupe_key` for non-terminal jobs prevents
duplicate concurrent jobs (e.g. two installs of the same app).

### State machine

```
queued ──claim──▶ running ──all steps done──▶ succeeded
  ▲                 │
  │ retryable error │ permanent error / attempts exhausted / cancel
  └──(backoff)──────┤
                    ▼
               compensating ──reverse Compensate of done steps──▶ failed | cancelled
                    │
                    └─ compensation error ──▶ failed + needs_attention
```

- Claiming increments `attempts`. A crash-interrupted attempt counts, so a job
  that crashes the process repeatedly ends as failed instead of crash-looping.
- Retryable errors requeue with exponential backoff (2 s × 2^(n−1), max 5 min).
  `jobs.Permanent(err)` marks an error as not retryable.
- Cancellation sets a flag; queued jobs are cancelled immediately (after
  compensating any steps done in an earlier attempt), running jobs have their
  step context cancelled at the next heartbeat.

### Crash recovery

- On startup, before workers start, jobs left `running` are requeued (or sent
  to compensation if attempts are exhausted) and compensation leases are
  cleared. Step journal entries tell the runner where to resume.
- Each job transition and step completion is a separate SQLite transaction
  with `synchronous=FULL` (ADR-0004), so a committed step survives power loss.
- Leases (30 s, renewed every 10 s) keep workers from picking up the same
  job; the Core runs as a single systemd instance.

### Graceful shutdown

`Runner.Stop` stops claiming, cancels running steps after the server's
shutdown timeout and requeues interrupted jobs *without* consuming an attempt.

### API

| Method & path | Permission |
|---|---|
| `GET /api/v1/jobs?state=&kind=&limit=` | `jobs.read` (all roles) |
| `GET /api/v1/jobs/{id}` (with steps and logs) | `jobs.read` |
| `POST /api/v1/jobs/{id}/cancel` | `jobs.manage` (owner, admin, operator); audited |

### Built-in kinds

- `maintenance.purge_sessions` — deletes expired sessions (hourly, deduplicated).
- `maintenance.purge_jobs` — deletes finished jobs older than 30 days (daily).

## Acceptance criteria → tests

| AT | Tests |
|---|---|
| AT-F18-01 | journal resumes after restart; outputs passed between steps; retries with backoff; permanent failure compensates in reverse order; dedupe; cancel queued and running jobs; compensation failure flags needs_attention; shutdown requeues without consuming an attempt; logs bounded |
| AT-F18-02 | real process killed with SIGKILL during every step and during compensation, restarted, job completes (or rolls back) with each side effect applied exactly once and a consistent journal |
| AT-F18-04 | WAL + `synchronous=FULL` verified (M1). VM-reset power-loss test is blocked by B-2 |
| AT-F09-01 | new routes in the contract test, OpenAPI and RBAC matrix |

## Security considerations

- No endpoint creates jobs or accepts job kinds/payloads from clients;
  payloads come from server-side modules only.
- Cancel is audited; job details are visible to all roles (no secrets in
  payloads or logs — modules must store secrets elsewhere, enforced by review).

## Known limitations

- Single Core instance assumed (systemd); leases are not a distributed lock.
- At-least-once execution: non-idempotent step implementations are bugs.
- Power-loss testing with a real VM reset needs B-2.

## Verification evidence (2026-10-27, branch `m3-jobs`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` | `khv01-dev`, Go 1.27.3 | Passed (without `-race` locally) |
| `internal/core/jobs`: 13 component tests (outputs, retry from journal, reverse compensation, attempts exhausted, cancel queued/running, compensation failure, shutdown requeue, recovery, dedupe, validation, unknown kind, bounded logs, purge) | `khv01-dev` | Passed |
| `internal/core/jobs`: SIGKILL of a real process in each of 4 steps and during rollback, then restart; effects applied exactly once, completed steps and compensations not repeated | `khv01-dev` | Passed (5 scenarios) |
| `internal/core/app`: maintenance jobs through the real runner and API; cancel with RBAC and audit; RBAC matrix and OpenAPI contract include the job routes | `khv01-dev` | Passed |
| CI | GitHub Actions | Pending |
