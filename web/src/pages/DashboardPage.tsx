import { JobProgress, JobStateBadge } from "../components/JobBits";
import { Alert, Badge, Card, PageHeader, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { formatDateTime, formatRelative } from "../lib/format";
import { Link } from "../lib/router";
import { useCurrentSession, useSession } from "../lib/session";
import { ACTIVE_JOB_STATES, type AgentStatus, type Alert as AlertItem, type AuditEvent, type HostMetrics, type Job, type JobState, type Version } from "../lib/types";
import { useData } from "../lib/useData";
import { AlertList } from "./AlertsPage";
import { HostSummary, ServiceList } from "./MonitoringPage";

function PlatformCard() {
  const { data, error, loading } = useData(async () => {
    const [ready, version, agent] = await Promise.all([
      fetch("/api/v1/health/ready", { credentials: "same-origin" }).then((r) => r.ok),
      api.get<Version>("/version"),
      api.get<AgentStatus>("/system/agent"),
    ]);
    return { ready, version, agent };
  }, []);
  return (
    <Card title="Platform">
      {loading && <Spinner />}
      {error && <Alert>{error}</Alert>}
      {data && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
          <dt className="text-slate-600 dark:text-slate-400">Core</dt>
          <dd>{data.ready ? <Badge tone="green">Ready</Badge> : <Badge tone="red">Not ready</Badge>}</dd>
          <dt className="text-slate-600 dark:text-slate-400">Host agent</dt>
          <dd>
            {data.agent.agent.available ? <Badge tone="green">Connected</Badge> : <Badge tone="amber">Unavailable</Badge>}
            {data.agent.agent.error && <span className="ml-2 text-xs text-slate-600 dark:text-slate-400">{data.agent.agent.error}</span>}
          </dd>
          <dt className="text-slate-600 dark:text-slate-400">Docker</dt>
          <dd>
            {data.agent.docker.available && data.agent.docker.info ? (
              <>
                <Badge tone="green">{data.agent.docker.info.server_version}</Badge>{" "}
                <span className="text-xs text-slate-600 dark:text-slate-400">
                  {data.agent.docker.info.running} running / {data.agent.docker.info.containers} containers
                  {data.agent.docker.info.rootless ? " · rootless" : ""}
                </span>
              </>
            ) : (
              <span className="text-xs text-slate-600 dark:text-slate-400">{data.agent.docker.error ?? "Unavailable"}</span>
            )}
          </dd>
          <dt className="text-slate-600 dark:text-slate-400">Version</dt>
          <dd className="break-all">{data.version.version}</dd>
          <dt className="text-slate-600 dark:text-slate-400">Commit</dt>
          <dd className="break-all font-mono text-xs">{data.version.commit.slice(0, 12)}</dd>
          <dt className="text-slate-600 dark:text-slate-400">Built</dt>
          <dd>{formatDateTime(data.version.build_date)}</dd>
        </dl>
      )}
    </Card>
  );
}

function HostCard() {
  const { data, error } = useData(() => api.get<HostMetrics>("/metrics/host"), [], { refreshMs: 15000 });
  return (
    <Card
      title="Host"
      actions={
        <Link to="/monitoring" className="text-sm text-brand-700 underline dark:text-brand-500">
          Monitoring
        </Link>
      }
    >
      {data ? <HostSummary host={data} /> : error ? <p className="text-sm text-slate-600 dark:text-slate-400">{error}</p> : <Spinner />}
    </Card>
  );
}

function AlertsCard() {
  const { data, error } = useData(() => api.get<{ alerts: AlertItem[] }>("/alerts?state=firing"), [], { refreshMs: 15000, live: ["alerts"] });
  return (
    <Card
      title="Alerts"
      actions={
        <Link to="/alerts" className="text-sm text-brand-700 underline dark:text-brand-500">
          All alerts
        </Link>
      }
    >
      {data ? <AlertList alerts={data.alerts.slice(0, 5)} empty="Nothing is wrong right now." /> : error ? <p className="text-sm">{error}</p> : <Spinner />}
    </Card>
  );
}

function JobsCard() {
  const { data, error, loading } = useData(() => api.get<{ jobs: Job[] }>("/jobs?limit=200"), [], {
    refreshMs: 3000,
    shouldPoll: (d) => d.jobs.some((j) => ACTIVE_JOB_STATES.includes(j.state)),
    live: ["jobs"],
  });
  const counts = new Map<JobState, number>();
  data?.jobs.forEach((j) => counts.set(j.state, (counts.get(j.state) ?? 0) + 1));
  const attention = data?.jobs.filter((j) => j.needs_attention).length ?? 0;
  return (
    <Card title="Jobs" actions={<Link to="/jobs" className="text-sm font-medium text-brand-700 underline dark:text-brand-500">All jobs</Link>}>
      {loading && <Spinner />}
      {error && <Alert>{error}</Alert>}
      {data && (
        <>
          {attention > 0 && (
            <div className="mb-3">
              <Alert kind="warning">{attention} job(s) need manual attention after a failed rollback.</Alert>
            </div>
          )}
          <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">
            {["running", "queued", "failed"].map((s) => `${counts.get(s as JobState) ?? 0} ${s}`).join(" · ")} (last 200)
          </p>
          {data.jobs.length === 0 ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">No jobs yet.</p>
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {data.jobs.slice(0, 5).map((j) => (
                <li key={j.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
                  <Link to={`/jobs/${j.id}`} className="font-medium underline-offset-2 hover:underline">
                    #{j.id} {j.kind}
                  </Link>
                  <span className="flex items-center gap-3">
                    <JobProgress job={j} />
                    <JobStateBadge state={j.state} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Card>
  );
}

function SecurityCard() {
  const { data, error, loading } = useData(() => api.get<{ events: AuditEvent[] }>("/audit?limit=50"), []);
  const failures = data?.events.filter((e) => e.result !== "success") ?? [];
  return (
    <Card title="Recent security events" actions={<Link to="/audit" className="text-sm font-medium text-brand-700 underline dark:text-brand-500">Audit log</Link>}>
      {loading && <Spinner />}
      {error && <Alert>{error}</Alert>}
      {data && (
        <>
          <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">
            {failures.length} failed or denied action(s) in the last {data.events.length} events.
          </p>
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {data.events.slice(0, 6).map((e) => (
              <li key={e.seq} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <span>
                  <span className="font-medium">{e.actor}</span> · {e.action}
                </span>
                <span className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
                  {formatRelative(e.time)}
                  <Badge tone={e.result === "success" ? "green" : e.result === "denied" ? "amber" : "red"}>{e.result}</Badge>
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

function SessionCard() {
  const session = useCurrentSession();
  return (
    <Card title="Your session">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
        <dt className="text-slate-600 dark:text-slate-400">Signed in as</dt>
        <dd>{session.user.username}</dd>
        <dt className="text-slate-600 dark:text-slate-400">Role</dt>
        <dd className="capitalize">{session.user.role}</dd>
        <dt className="text-slate-600 dark:text-slate-400">Expires</dt>
        <dd>{formatRelative(session.expires_at)} at the latest</dd>
      </dl>
      <Link to="/account" className="mt-3 inline-block text-sm font-medium text-brand-700 underline dark:text-brand-500">
        Manage sessions and password
      </Link>
    </Card>
  );
}

export function DashboardPage() {
  const { can } = useSession();
  return (
    <>
      <PageHeader title="Dashboard" description="Current state of this Kernhaven instance." />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <PlatformCard />
        {can("alerts.read") && <AlertsCard />}
        {can("system.read") && <HostCard />}
        {can("system.read") && (
          <Card title="Services">
            <ServiceList />
          </Card>
        )}
        <SessionCard />
        {can("jobs.read") && <JobsCard />}
        {can("audit.read") && <SecurityCard />}
      </div>
    </>
  );
}
