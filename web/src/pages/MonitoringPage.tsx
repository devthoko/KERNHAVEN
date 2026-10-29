import { useState } from "react";
import { Chart, formatValue, type Line } from "../components/Chart";
import { Alert, Badge, Card, PageHeader, Spinner, Table, td, th } from "../components/ui";
import { api } from "../lib/api";
import { formatBytes, formatDateTime } from "../lib/format";
import { useSession } from "../lib/session";
import type { ContainerMetrics, HostMetrics, MetricHistory, ServiceCheck } from "../lib/types";
import { useData } from "../lib/useData";

type Range = "1h" | "24h" | "7d";
const ranges: { value: Range; label: string }[] = [
  { value: "1h", label: "1 hour" },
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
];
const blue = "stroke-brand-700 dark:stroke-brand-500";
const amber = "stroke-amber-600 dark:stroke-amber-400";

function useHistory(keys: string[], range: Range) {
  return useData(
    () => Promise.all(keys.map((k) => api.get<MetricHistory>(`/metrics/history?series=${encodeURIComponent(k)}&range=${range}`))),
    [keys.join(","), range],
    { refreshMs: range === "1h" ? 15000 : 60000 },
  );
}

function HistoryChart({ title, keys, labels, range }: { title: string; keys: string[]; labels: string[]; range: Range }) {
  const { data, error } = useHistory(keys, range);
  if (error) return <Alert>{error}</Alert>;
  if (!data) return <Spinner />;
  const lines: Line[] = data.map((h, i) => ({ label: labels[i] ?? h.series, points: h.points, className: i === 0 ? blue : amber }));
  return <Chart title={title} unit={data[0]?.unit ?? ""} lines={lines} long={range === "7d"} />;
}

/** ServiceList shows the health of every service (AT-F13-04). */
export function ServiceList() {
  const { data, error, loading } = useData(() => api.get<{ services: ServiceCheck[] }>("/health/services"), [], { refreshMs: 15000 });
  if (loading && !data) return <Spinner />;
  if (!data) return <Alert>{error ?? "Unavailable"}</Alert>;
  return (
    <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800" aria-label="Services">
      {data.services.map((s) => (
        <li key={s.name} className="flex flex-wrap items-center justify-between gap-2 py-2">
          <span className="font-medium">{s.label}</span>
          <span className="flex flex-wrap items-center justify-end gap-2">
            {s.detail && <span className="text-xs text-slate-600 dark:text-slate-400">{s.detail}</span>}
            {s.status === "ok" ? <Badge tone="green">running</Badge> : s.status === "down" ? <Badge tone="red">down</Badge> : <Badge>not configured</Badge>}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** HostSummary shows the latest host reading (AT-F13-01). */
export function HostSummary({ host }: { host: HostMetrics }) {
  const memPct = host.memory.total ? (host.memory_used / host.memory.total) * 100 : 0;
  const rx = host.interfaces.reduce((a, i) => a + i.in, 0);
  const tx = host.interfaces.reduce((a, i) => a + i.out, 0);
  const rd = host.disks.reduce((a, d) => a + d.in, 0);
  const wr = host.disks.reduce((a, d) => a + d.out, 0);
  const hottest = host.temperatures.reduce<number | null>((m, t) => (m === null || t.celsius > m ? t.celsius : m), null);
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm sm:grid-cols-3">
      <div>
        <dt className="text-slate-600 dark:text-slate-400">CPU ({host.cpus})</dt>
        <dd className="text-lg font-semibold">{host.cpu_percent === null ? "…" : formatValue(host.cpu_percent, "percent")}</dd>
      </div>
      <div>
        <dt className="text-slate-600 dark:text-slate-400">Memory</dt>
        <dd className="text-lg font-semibold">
          {formatBytes(host.memory_used)} <span className="text-xs font-normal">of {formatBytes(host.memory.total)} ({memPct.toFixed(0)} %)</span>
        </dd>
      </div>
      <div>
        <dt className="text-slate-600 dark:text-slate-400">Load</dt>
        <dd className="text-lg font-semibold">{host.load.map((l) => l.toFixed(2)).join(" · ")}</dd>
      </div>
      <div>
        <dt className="text-slate-600 dark:text-slate-400">Disks</dt>
        <dd>
          ↓ {formatValue(rd, "bytes/s")} · ↑ {formatValue(wr, "bytes/s")}
        </dd>
      </div>
      <div>
        <dt className="text-slate-600 dark:text-slate-400">Network</dt>
        <dd>
          ↓ {formatValue(rx, "bytes/s")} · ↑ {formatValue(tx, "bytes/s")}
        </dd>
      </div>
      <div>
        <dt className="text-slate-600 dark:text-slate-400">Temperature</dt>
        <dd>{hottest === null ? "no sensors" : `${hottest.toFixed(0)} °C (hottest)`}</dd>
      </div>
    </dl>
  );
}

/** MonitoringPage shows host and container metrics with history (AT-F13-01..04). */
export function MonitoringPage() {
  const { can } = useSession();
  const [range, setRange] = useState<Range>("1h");
  const [selected, setSelected] = useState<string | null>(null);
  const host = useData(() => api.get<HostMetrics>("/metrics/host"), [], { refreshMs: 15000 });
  const containers = useData(
    () => (can("containers.read") ? api.get<{ containers: ContainerMetrics[] }>("/metrics/containers") : Promise.resolve({ containers: [] })),
    [],
    { refreshMs: 15000 },
  );
  const temps = host.data?.temperatures.slice(0, 4) ?? [];
  const key = (name: string) => name.toLowerCase().replace(/[^a-z0-9_.-]+/g, "_").replace(/^[_.]+|[_.]+$/g, "");

  return (
    <>
      <PageHeader
        title="Monitoring"
        description="Host and container metrics. History is kept for 7 days."
        actions={
          <div role="group" aria-label="Time range" className="inline-flex rounded-md border border-slate-300 dark:border-slate-600">
            {ranges.map((r) => (
              <button
                key={r.value}
                type="button"
                aria-pressed={range === r.value}
                onClick={() => setRange(r.value)}
                className={`min-h-10 px-3 text-sm ${range === r.value ? "bg-brand-700 text-white" : "hover:bg-slate-100 dark:hover:bg-slate-800"}`}
              >
                {r.label}
              </button>
            ))}
          </div>
        }
      />
      <div className="space-y-4">
        <Card title="Host">
          {host.data ? (
            <div className="space-y-3">
              <HostSummary host={host.data} />
              <p className="text-xs text-slate-600 dark:text-slate-400">Last reading {formatDateTime(host.data.sampled_at)}</p>
              {host.data.errors && <Alert kind="info">Not available on this host: {Object.keys(host.data.errors).join(", ")}.</Alert>}
            </div>
          ) : host.error ? (
            <Alert kind="info">{host.error}</Alert>
          ) : (
            <Spinner />
          )}
        </Card>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <HistoryChart title="CPU" keys={["host.cpu"]} labels={["busy"]} range={range} />
          </Card>
          <Card>
            <HistoryChart title="Memory used" keys={["host.memory"]} labels={["used"]} range={range} />
          </Card>
          <Card>
            <HistoryChart title="Load (1 minute)" keys={["host.load1"]} labels={["load"]} range={range} />
          </Card>
          <Card>
            <HistoryChart title="Disk I/O" keys={["host.disk_read", "host.disk_write"]} labels={["read", "write"]} range={range} />
          </Card>
          <Card>
            <HistoryChart title="Network" keys={["host.net_rx", "host.net_tx"]} labels={["received", "sent"]} range={range} />
          </Card>
          {temps.length > 0 && (
            <Card>
              <HistoryChart title={`Temperature ${temps[0]!.sensor}`} keys={[`host.temp.${key(temps[0]!.sensor)}`]} labels={[temps[0]!.sensor]} range={range} />
            </Card>
          )}
        </div>
        {can("containers.read") && (
          <Card title="Containers">
            {containers.error && <Alert kind="info">{containers.error}</Alert>}
            {containers.data && containers.data.containers.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">No running containers.</p>}
            {containers.data && containers.data.containers.length > 0 && (
              <Table
                caption="Running containers"
                head={
                  <tr>
                    <th className={th}>Container</th>
                    <th className={th}>CPU</th>
                    <th className={th}>Memory</th>
                    <th className={th}>Network ↓/↑</th>
                    <th className={th}>Disk read/write</th>
                  </tr>
                }
              >
                {containers.data.containers.map((c) => (
                  <tr key={c.id}>
                    <td className={td}>
                      <button type="button" className="font-medium text-brand-700 underline dark:text-brand-500" aria-expanded={selected === c.name} onClick={() => setSelected(selected === c.name ? null : c.name)}>
                        {c.name}
                      </button>
                    </td>
                    <td className={td}>{c.cpu_percent === null ? "…" : formatValue(c.cpu_percent, "percent")}</td>
                    <td className={td}>
                      {formatBytes(c.memory)}
                      {c.memory_limit > 0 && c.memory_limit < 1e15 && <span className="text-xs text-slate-600 dark:text-slate-400"> / {formatBytes(c.memory_limit)}</span>}
                    </td>
                    <td className={td}>{c.net_rx === null ? "…" : `${formatValue(c.net_rx, "bytes/s")} / ${formatValue(c.net_tx ?? 0, "bytes/s")}`}</td>
                    <td className={td}>{c.block_read === null ? "…" : `${formatValue(c.block_read, "bytes/s")} / ${formatValue(c.block_write ?? 0, "bytes/s")}`}</td>
                  </tr>
                ))}
              </Table>
            )}
            {selected && (
              <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
                <HistoryChart title={`${selected}: CPU`} keys={[`container.${key(selected)}.cpu`]} labels={["share of the host"]} range={range} />
                <HistoryChart title={`${selected}: memory`} keys={[`container.${key(selected)}.memory`]} labels={["used"]} range={range} />
              </div>
            )}
          </Card>
        )}
        <Card title="Services">
          <ServiceList />
        </Card>
      </div>
    </>
  );
}
