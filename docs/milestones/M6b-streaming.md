# M6b — Streaming: Exec Console, Live Status, Log Follow

Status: Implemented (CI 40958468980); merge pending owner review
Depends on: M4, M6, M11
Acceptance tests: AT-F02-07, AT-F01-05
Threats addressed: TH-25, TH-26 (below), TH-20 (no command from API input)

## Scope

| Part | Design |
|---|---|
| Console (AT-F02-07) | `POST /containers/{id}/console {shell: sh\|bash}` → console ID; output as server-sent events `GET /consoles/{id}/stream`; input `POST /consoles/{id}/input`; `DELETE /consoles/{id}` (ADR-0031) |
| Live status (AT-F01-05) | `GET /events` (server-sent events): `change` for containers, jobs, alerts — by permission; pages reload through the API; polling remains every 30 s as a safety net, and is used where `EventSource` is missing |
| Log follow | `GET /containers/{id}/logs/stream`: the last 200 lines, then new ones as written (30 minutes at most) |

Pages using live updates: dashboard (jobs, alerts), containers, container
detail, stacks, apps, jobs, alerts.

## Threats

| ID | Threat | Mitigation |
|---|---|---|
| TH-25 | E | The console is used to reach the host | Only sh/bash in managed, running containers; refused for privileged, host-PID and Docker-socket containers (agent-side check); container's own user; owner/admin with step-up; bound to the opening browser session; limits and timeouts; audited |
| TH-26 | I/D | Long-lived streams outlive a sign-out or exhaust the Core | Event streams end after 5 minutes (session checked on reconnect); at most 200 listeners; one shared poller; consoles end after 15 minutes idle / 1 hour; log follow ends after 30 minutes |

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F02-07 | `TestM6bConsoleAndFollow` (real Docker: shell as user 1000, input and output, exit code 3; refusals for an unmanaged container, another program and a missing container arrive as the first line while the input is open); `TestCheckExec` (privileged, Docker socket incl. rootless path, host PID, stopped, unmanaged refused); `TestConsoleThroughCore` (operators refused, arbitrary shell refused, output streamed, another user and another browser session of the same user refused, input limit, exit code, audit with metadata only — no typed text, 2 per user, step-up required); E2E (console, exit code, axe) |
| AT-F01-05 | `TestLiveEventsAndLogFollow` (kinds by permission: viewer without alerts; anonymous refused; job and container changes pushed after a deployment and a stop; log follow streams lines, viewer refused); `live.test.ts` (one shared stream, only subscribers of a kind, closed when the last leaves, fallback without EventSource); E2E (a stop in one tab shows in the container list of another within 10 s, while its fallback poll is 30 s) |

## Known limitations

- The console has no TTY: line based, no full-screen programs, no Ctrl-C
  to a running command (close the console instead).
- Live updates say that something changed, not what; pages reload the data.
- Container changes are detected by polling the agent every 2 s while
  someone watches (no Docker event stream).

## Verification evidence (2026-10-29, branch `m6b-streaming`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web) | `khv01-dev` | Passed |
| `TestM6bConsoleAndFollow` on real rootless Docker 29.9.2 | `khv01-dev` | Passed |
| `TestConsoleThroughCore`, `TestLiveEventsAndLogFollow` (5 runs), `TestCheckExec`, `live.test.ts`, contract, RBAC | `khv01-dev` | Passed — the first run hung: a refused console start was answered while the Core still streamed input, and Go's client waited for the input to end; the agent now confirms the stream first and sends refusals as the first line, and the Core bounds the start with a 30 s guard |
| CI full suite incl. race detector, real Docker on amd64/arm64 and browser E2E (console with exit code, a stop pushed to another tab's container list within its 30 s fallback, axe) | GitHub Actions | Passed (run 40958468980) — earlier runs found: (1) the container fingerprint included Docker's uptime text, so a change was announced every 2 s — now state and health only; (2) with a frozen test clock job transitions went unannounced on arm64 — the fingerprint now includes the latest jobs' states; (3) a slow runner needed more than 5 s to show a created container (E2E wait raised) |
