# ADR-0027: A monitor role for host readings; metrics in SQLite with fixed downsampling

- Status: Accepted
- Date: 2026-10-28

## Context
M14 needs host metrics, container metrics and 7 days of history. The Core's
unit hides `/proc` (`ProcSubset=pid`). The existing agent roles are the
Docker agent (root-equivalent through the docker group), the storage and
file services (root) and the proxy service (talks to Caddy's admin API).
Time-series databases (Prometheus, InfluxDB) would add a service, a port and
upgrades to maintain.

## Decision
- A fifth role of the agent binary, `role = "monitor"`, runs as its own
  unprivileged user without capabilities or IP traffic, in the host's
  network namespace (for `/proc/net/dev`), with `/proc` fully visible and the
  file system read-only. It offers `agent.info` and `host.metrics` (raw
  counters) only.
- Container stats come from the Docker agent (`containers.stats`, one-shot
  stats per running container).
- The Core computes rates, keeps one hour of raw samples in memory and
  stores 1-minute and 15-minute averages and maxima in SQLite
  (`metric_points`, `WITHOUT ROWID`), pruned to 24 hours and 7 days, with at
  most 300 series.

## Consequences
- No new external service; storage is bounded by construction (about
  25 MB at most).
- One more unit and system user for the installer (M18).
- Raw samples are lost on restart; history starts again at 1-minute
  resolution.
- Temperatures depend on the kernel's hwmon drivers; virtual machines often
  have none.
