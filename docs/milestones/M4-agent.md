# M4 — Host Agent and Privilege Boundary

Status: In progress
Depends on: M2 (identity, audit), M3 (jobs)
Threats addressed: TH-20, TH-21 (framework), TH-22, TH-23, TH-24, TH-34
Acceptance tests: AT-M4-01 … AT-M4-08 (below); they become prerequisites of F02 (M6)

## Goal

A separate `kernhaven-agent` process is the only component that talks to the
Docker Engine (ADR-0003, ADR-0005). The Core reaches it over a unix socket and
can only ask for typed, allow-listed operations, each carrying a short-lived
grant signed by the Core. The agent validates everything again on its own.
M4 delivers the boundary, the protocol, a minimal Docker client, read-only
operations and container start/stop/restart; the full container feature set
and its UI follow in M6.

## Design

### Processes

| | Core | Agent |
|---|---|---|
| User (production) | `kernhaven` | `kernhaven-agent` (member of `docker`) |
| Listens on | 127.0.0.1 (HTTP) | `/run/kernhaven/agent.sock` only |
| Docker socket | never | `/run/docker.sock` (or rootless socket in development) |
| Network | loopback | none (`RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`) |

### Transport and authentication

1. **Unix socket, file permissions:** socket mode `0660`, group `kernhaven-agent-clients`
   whose only member is the Core user; parent directory `0750`.
2. **Peer credentials:** on every connection the agent reads `SO_PEERCRED` and
   rejects peers whose UID is not in `allowed_uids` (TH-22).
3. **Signed grants (Ed25519):** every request carries a grant
   `{op, params_sha256, actor, request_id, nonce, issued_at, expires_at}` signed
   with the Core's private key (`<data_dir>/agent-grant.key`, 0600, created on
   first start). The agent holds only the public key, from a root-owned path
   in production. Checks: signature, `op` and `params_sha256` match the
   request, lifetime ≤ 60 s with 5 s clock skew, nonce not seen before (TH-23).
4. **Size and time limits:** requests ≤ 64 KiB, strict JSON decoding with
   unknown fields rejected, server timeouts (TH-24).

The grant does not stop a fully compromised Core (it holds the private key);
that residual risk is AR-02. It does stop other local processes, replays and
parameter substitution, and it lets the agent log *who* asked for an action.

### Operations (allow-list, TH-20/TH-34)

Each operation is a Go type with a validated parameter struct; there is no
generic exec, shell or Docker API passthrough.

| Operation | Parameters | Docker call |
|---|---|---|
| `agent.info` | — | — (agent version, uptime) |
| `docker.info` | — | `GET /_ping`, `/version`, `/info` |
| `containers.list` | `all bool` | `GET /containers/json` |
| `containers.inspect` | `id` | `GET /containers/{id}/json` (summary only) |
| `containers.start` / `stop` / `restart` | `id`, `timeout_seconds` (0–300, stop/restart) | `POST /containers/{id}/…` |

Container references must match `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$` (ID or
name); they are path-escaped when building Docker API URLs.

### Docker client

- Minimal client over the unix socket with `net/http`; no Docker SDK
  (large dependency tree).
- API version negotiated once: `min(1.47, daemon ApiVersion)`; the agent
  refuses daemons older than 1.44.
- Docker errors are mapped to typed errors: not found, conflict,
  unavailable (daemon down, socket missing, timeout). The agent never
  crashes or hangs on Docker failures; each call has a timeout.

### Core side

- `internal/core/agentclient`: signs grants, calls the agent, maps errors.
- Configuration `[agent] socket = "/run/kernhaven/agent.sock"`; when the
  socket is absent the Core runs and reports the agent as unavailable.
- API: `GET /api/v1/system/agent` (`system.read`) → agent and Docker status.
  The dashboard shows it. Container endpoints come with M6.

### Agent configuration (`/etc/kernhaven/agent.toml`)

```toml
socket = "/run/kernhaven/agent.sock"
allowed_uids = [998]                         # Core service user
grant_public_key = "/etc/kernhaven/agent-grant.pub"
docker_socket = "/run/docker.sock"
[log]
level = "info"
```

## Acceptance criteria → tests

| ID | Criterion | Tests |
|---|---|---|
| AT-M4-01 | Only allow-listed operations exist; unknown operations are rejected | registry test pins the exact operation list; unknown op → 404 |
| AT-M4-02 | Peers with a UID outside `allowed_uids` are rejected before any request is processed | socket test with an allow-list excluding the test UID |
| AT-M4-03 | Missing, expired, future, forged, wrong-key, wrong-op and wrong-params grants are rejected | grant unit tests + socket tests |
| AT-M4-04 | Replayed grants are rejected | nonce cache tests |
| AT-M4-05 | Invalid parameters (unknown fields, bad IDs, out-of-range timeouts, oversized bodies) are rejected without reaching Docker | param validation tests with a Docker stub that fails on any call |
| AT-M4-06 | Operations work against a real Docker Engine | integration tests (`-tags integration`) on rootless Docker (dev) and rootful Docker (CI runners) |
| AT-M4-07 | Docker failures are reported as "unavailable" and do not crash the agent or Core | tests with a stopped/missing Docker socket and a hanging fake daemon |
| AT-M4-08 | Core reports agent and Docker status end-to-end | app test with a real agent on a temp socket |
| — | Malformed input never crashes the agent | Go fuzz tests for envelope and grant decoding (seed corpus in CI) |

## Security considerations

- The agent user is effectively root through the Docker socket; the agent
  is therefore minimal, has no network access and only typed operations.
- The grant key is generated by the Core; production installs (M18) copy the
  public key to a root-owned path so the Core cannot replace it at runtime.
- Development on `khv01-dev` uses rootless Docker owned by `dev01`; neither
  Claude nor the tests get root-equivalent rights on the host.

## Known limitations

- Rootful-Docker deployment with separate users is verified only as far as
  CI runners allow (agent and tests share one user there); full verification
  needs the Debian 13 VMs (B-2) and the installer (M18).
- Container policy evaluation (TH-21) arrives with container creation in M6;
  M4 has no operation that creates containers.

## Verification evidence (2026-10-27, branch `m4-agent`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web, staticcheck, govulncheck, builds of both binaries for amd64/arm64) | `khv01-dev` | Passed |
| Protocol tests: round trip; 13 invalid-grant cases; key file permissions | `khv01-dev` | Passed |
| Agent socket tests: pinned allow-list (AT-M4-01), foreign UID rejected before any request (AT-M4-02), missing/expired/forged/other-op/substituted-params grants (AT-M4-03), replay (AT-M4-04), 9 invalid-parameter cases + unknown op + oversized body + unknown envelope field with Docker never called (AT-M4-05), Docker error mapping (AT-M4-07) | `khv01-dev` | Passed |
| Docker client against fake daemons: version negotiation, too-old daemon, 404/409/304/500 mapping, missing socket, hanging daemon timeout, path escaping | `khv01-dev` | Passed |
| Agent process: runs without Docker, reports `docker_unavailable`, stays up, SIGTERM exit 0, socket removed | `khv01-dev` | Passed |
| Core: status API with absent agent, with agent + Docker up, with agent + Docker down (AT-M4-08); key file 0600 | `khv01-dev` | Passed |
| Integration (AT-M4-06): Core client → signed grant → agent → real rootless Docker 29.9.2 (API 1.56, negotiated 1.47): info, list with labels, inspect, start (+idempotent), restart, stop (+idempotent), not-found; test containers removed | `khv01-dev` | Passed |
| Fuzzing: `FuzzVerify` 30 s (≈427k execs), `FuzzHandleOp` 45 s (≈299k execs), no crashes | `khv01-dev` | Passed (one harness bug fixed: unescaped control characters in the test URL) |
| Live: real `kernhaven-core` + `kernhaven-agent` binaries, setup via API, `GET /api/v1/system/agent` → agent and rootless Docker available; socket 0660, grant key 0600; agent log records actor and request ID | `khv01-dev` | Passed |
| systemd: `kernhaven-agent.service` verify + exposure 0.7 | `khv01-dev` | Passed |
| CI incl. integration on rootful Docker (amd64, arm64) and 60 s fuzzing | GitHub Actions | Pending |
