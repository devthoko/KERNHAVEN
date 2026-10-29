# M14 — System and Container Monitoring

Status: Implemented (CI pending); merge pending owner review
Depends on: M4, M6 (and M9–M13 for the services whose health is shown)
Acceptance tests: AT-F13-01 … AT-F13-04
Threats addressed: TH-06 (resource use of the collector), TH-18 (below)

## Where numbers come from (ADR-0027)

| Source | Process | Reads |
|---|---|---|
| Host metrics | new agent role `monitor` (`kernhaven-monitor.service`, user `kernhaven-monitor`, no capabilities, no IP traffic, read-only system) | `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/diskstats`, `/proc/net/dev`, `/sys/class/hwmon` |
| Container metrics | Docker agent, new operation `containers.stats` | Docker's one-shot stats of running containers |
| Service health | Core | `agent.info` of every agent role, `docker.info`, `proxy.status` |

The Core's own unit hides `/proc` (`ProcSubset=pid`); giving it, the proxy
or the storage service more access would mix privileges, so host readings
get a fifth, least-privileged role. It offers only `agent.info` and
`host.metrics`.

## Host metrics (AT-F13-01)

`host.metrics` returns raw counters; the Core turns them into rates:

- CPU: busy share of all CPUs (from `/proc/stat` jiffies), CPU count;
- memory: total, available, used (= total − available), swap used;
- load: 1, 5, 15 minutes;
- disk I/O: bytes read and written per second, per whole disk (no
  partitions, loop or RAM devices) and in total;
- network: bytes received and sent per second, per interface (without `lo`)
  and in total;
- temperatures: every hwmon sensor (`tempN_input`), named
  `<chip>/<label>`; missing sensors are not an error.

## Container metrics (AT-F13-02)

Per running container: CPU share (of the host's CPUs), memory used and
limit, network and block I/O per second.

## History (AT-F13-03)

The Core samples every 15 s (`[metrics] interval`, 5–60 s).

| Resolution | Kept | Where |
|---|---|---|
| raw (15 s) | 1 hour | memory (lost on restart) |
| 1 minute (average and maximum) | 24 hours | SQLite |
| 15 minutes (average and maximum) | 7 days | SQLite |

At most 300 series are stored (host series first; containers in the order
they appear); further series are not recorded and a warning is logged once.
The bound is therefore 300 × (1 440 + 672) points ≈ 634 000 rows
(about 25 MB). Points older than their retention, and series without data
for 7 days, are deleted every 15 minutes.

## Service health (AT-F13-04)

`GET /api/v1/health/services`: Core (version, uptime, database), Docker agent
and Docker Engine, storage service, file service, proxy service and Caddy
(reachable, configuration in sync), monitor service — each `ok`, `down`
(with the reason) or `not_configured`. Shown on the dashboard.

## API

| Route | Permission |
|---|---|
| `GET /api/v1/metrics/host` | `system.read` |
| `GET /api/v1/metrics/containers` | `containers.read` |
| `GET /api/v1/metrics/history?series=…&range=1h\|24h\|7d` | `system.read` (host series), `containers.read` (container series) |
| `GET /api/v1/metrics/series` | `system.read` (container series only with `containers.read`) |
| `GET /api/v1/health/services` | `system.read` |

## Threats

| ID | Threat | Mitigation |
|---|---|---|
| TH-18 | Monitoring exhausts disk or CPU (many containers, long uptime) | Fixed sampling interval bounds, 300-series cap, retention pruning; one Docker call per running container per sample with a timeout |

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F13-01 | `internal/agent/monitor` `TestFixture` (CPU without guest double counting and with iowait as idle, memory, load, whole disks only, interfaces without `lo`, hwmon labels, missing sources reported), `TestRealHost`; `TestMetricsNow` (rates from two readings of the real monitor role on fixtures: CPU 15 %, disk and network bytes/s, temperature); CI job `proxy`: the real `kernhaven-monitor` unit reads the host's counters in its sandbox; E2E: host card and monitoring page |
| AT-F13-02 | `TestM6ContainersImagesVolumesNetworks` (one-shot stats of a running container from real Docker: CPU and system time, memory, the 64 MiB limit); `TestMetricsNow` (CPU as share of the whole host, not of one CPU; memory, network and block I/O rates); E2E: container table |
| AT-F13-03 | `TestMetricsHistory` (40 minutes of samples → 40 one-minute and 2 fifteen-minute points with correct averages and maxima and bucket starts; minute points pruned after 24 h, quarter points and idle series after 7 days; at most 300 series, logged once); range validation |
| AT-F13-04 | `TestServiceHealth` (ok, not_configured, down with the reason); E2E: services on the dashboard |

## Known limitations

- Raw 15-second samples live in memory: after a restart the last hour starts
  empty; 1-minute and 15-minute history survive.
- Temperatures only where the kernel exposes hwmon sensors (often none in
  virtual machines; the development server has none).
- File system usage is not part of monitoring; the storage page (M9) shows it.
- Container series are keyed by name; a container re-created under the same
  name continues its series.
- No alerts yet: thresholds and notifications are M15.

## Verification evidence (2026-10-29, branch `m14-monitoring`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed — staticcheck first found an unused assignment in a test |
| `internal/agent/monitor` (`TestFixture`, `TestRealHost`), allow-lists (monitor role: `agent.info`, `host.metrics`; Docker agent: `containers.stats`) | `khv01-dev` | Passed |
| Docker stats against real rootless Docker 29.9.2 (`TestM6ContainersImagesVolumesNetworks`) | `khv01-dev` | Passed |
| `TestMetricsNow`, `TestMetricsHistory`, `TestServiceHealth`, contract (132 operations), RBAC | `khv01-dev` | Passed |
| Mutation checks: no minute retention, no series cap, iowait counted as busy, container CPU per CPU instead of per host (found only after the test used 4 CPUs) — each makes a test fail | `khv01-dev` | Passed |
| systemd exposure: `kernhaven-monitor` 0.8 (threshold 2.0) | `khv01-dev` | Passed |
| Live with real binaries (Core, monitor role, Docker agent, rootless Docker, 5 s sampling): a busy-loop container shows 16.7 % (one of six CPUs), the host 16.9 %; memory, load, disk and network rates; 1-hour and 1-minute history; services ok / not configured | `khv01-dev` | Passed |
| UI check: monitoring page with charts, container table, dashboard host and services cards, 375 px without horizontal overflow | `khv01-dev` | Passed — the first chart version scaled its axis labels with the SVG and was unreadable; labels are HTML now |
| First full CI run (40836136980) | GitHub Actions | Failed: only E2E — the dashboard test's `Host agent` text now also matched the new services list (selector scoped to the platform card). All other jobs passed, including the real monitor unit and Docker stats on amd64/arm64 |
| CI full suite: real monitor unit, Docker stats on amd64/arm64, browser E2E | GitHub Actions | pending |
