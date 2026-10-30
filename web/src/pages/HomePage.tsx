import { Icon, type IconName } from "../components/Icon";
import { isHousekeeping, jobTitle, JobStateBadge } from "../components/JobBits";
import { Avatar, Card, EmptyState, Meter, Spinner } from "../components/ui";
import { formatValue } from "../components/Chart";
import { api } from "../lib/api";
import { formatBytes, formatRelative } from "../lib/format";
import { Link } from "../lib/router";
import { useCurrentSession, useSession } from "../lib/session";
import { ACTIVE_JOB_STATES, type Alert as AlertItem, type FileSystemInfo, type HostMetrics, type InstalledApp, type Job, type SecurityOverview, type ServiceCheck, type StorageInventory } from "../lib/types";
import { useData } from "../lib/useData";
import { webURL } from "./AppsPage";

const muted = "text-slate-600 dark:text-slate-400";

function greeting(hour: number): string {
  if (hour < 5) return "Good evening";
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

// ---- system widgets ----

function Widget({ icon, label, value, detail, percent }: { icon: IconName; label: string; value: string; detail?: string; percent?: number }) {
  return (
    <div className="min-w-0 rounded-xl border border-slate-200 bg-white p-3.5 shadow-sm sm:p-4 dark:border-white/10 dark:bg-slate-900">
      <div className={`flex items-center gap-2 text-sm font-medium ${muted}`}>
        <Icon name={icon} className="size-4" />
        {label}
      </div>
      <p className="mt-2 truncate text-xl font-semibold tabular-nums tracking-tight sm:text-2xl">{value}</p>
      {percent !== undefined && <Meter percent={percent} className="mt-3" />}
      {detail && <p className={`mt-2 truncate text-xs ${muted}`}>{detail}</p>}
    </div>
  );
}

/** largestFileSystem picks the file system people care about most: the system root, else the biggest one. */
export function largestFileSystem(inv: StorageInventory): FileSystemInfo | null {
  const all = inv.disks.flatMap((d) => d.file_systems).filter((f) => f.fs_size_bytes > 0);
  return all.find((f) => f.mountpoints.includes("/")) ?? all.sort((a, b) => b.fs_size_bytes - a.fs_size_bytes)[0] ?? null;
}

function SystemWidgets() {
  const { can } = useSession();
  const host = useData(() => api.get<HostMetrics>("/metrics/host"), [], { refreshMs: 15000 });
  const storage = useData(() => (can("storage.read") ? api.get<StorageInventory>("/storage") : Promise.resolve(null)), []);
  const h = host.data;
  const fs = storage.data ? largestFileSystem(storage.data) : null;
  if (!h) {
    if (!host.error) return <Spinner label="Reading the system" />;
    return (
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        {(
          [
            ["cpu", "Processor"],
            ["memory", "Memory"],
            ["disk", "Storage"],
            ["network", "Network"],
          ] as const
        ).map(([icon, label]) => (
          <Widget key={label} icon={icon} label={label} value="—" detail="No reading yet: the monitor service is not reachable." />
        ))}
      </div>
    );
  }
  const memPct = h.memory.total ? (h.memory_used / h.memory.total) * 100 : 0;
  const rx = h.interfaces.reduce((a, i) => a + i.in, 0);
  const tx = h.interfaces.reduce((a, i) => a + i.out, 0);
  return (
    <section aria-labelledby="system-heading">
      <h2 id="system-heading" className="sr-only">
        System
      </h2>
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <Widget
          icon="cpu"
          label="Processor"
          value={h.cpu_percent === null ? "—" : formatValue(h.cpu_percent, "percent")}
          percent={h.cpu_percent ?? 0}
          detail={`${h.cpus} cores · load ${h.load[0].toFixed(2)}`}
        />
        <Widget icon="memory" label="Memory" value={`${memPct.toFixed(0)} %`} percent={memPct} detail={`${formatBytes(h.memory_used)} of ${formatBytes(h.memory.total)}`} />
        {fs ? (
          <Widget
            icon="disk"
            label="Storage"
            value={`${Math.round((fs.fs_used_bytes / fs.fs_size_bytes) * 100)} %`}
            percent={(fs.fs_used_bytes / fs.fs_size_bytes) * 100}
            detail={`${formatBytes(fs.fs_available_bytes)} free of ${formatBytes(fs.fs_size_bytes)}`}
          />
        ) : (
          <Widget icon="disk" label="Storage" value="—" detail={can("storage.read") ? "No file system reported" : "Needs storage access"} />
        )}
        <Widget icon="network" label="Network" value={`↓ ${formatValue(rx, "bytes/s")}`} detail={`↑ ${formatValue(tx, "bytes/s")} sent`} />
      </div>
    </section>
  );
}

// ---- apps ----

function AppTile({ app }: { app: InstalledApp }) {
  const url = app.url || (app.web_port > 0 ? webURL(app.web_port) : "");
  const running = app.status === "deployed";
  const status = running ? "Running" : app.status === "deploying" ? "Starting" : app.status === "failed" ? "Failed" : app.status === "stopped" ? "Stopped" : app.status;
  const dot = running ? "bg-emerald-500" : app.status === "failed" ? "bg-red-500" : app.status === "deploying" || app.status === "stopping" ? "bg-sky-500" : "bg-slate-400";
  const body = (
    <>
      <Avatar name={app.name} className="size-14 text-lg" rounded="rounded-2xl" />
      <span className="mt-3 block max-w-full truncate text-sm font-medium">{app.name}</span>
      <span className={`mt-1 flex items-center gap-1.5 text-xs ${muted}`}>
        <span className={`size-1.5 rounded-full ${dot}`} aria-hidden="true" />
        {status}
        {app.update_available && <span className="text-sky-700 dark:text-sky-300">· update</span>}
      </span>
    </>
  );
  const tile =
    "flex h-full flex-col items-center rounded-2xl border border-slate-200 bg-white px-3 pb-4 pt-5 text-center shadow-sm transition hover:-translate-y-0.5 hover:shadow-md motion-reduce:transition-none motion-reduce:hover:translate-y-0 dark:border-white/10 dark:bg-slate-900 dark:hover:border-white/20";
  return (
    <li className="relative">
      {url && running ? (
        <a href={url} target="_blank" rel="noopener noreferrer" className={tile} aria-label={`Open ${app.name} (new tab)`}>
          {body}
        </a>
      ) : (
        <Link to={`/apps/${app.name}`} className={tile} aria-label={`${app.name}: ${status}`}>
          {body}
        </Link>
      )}
      <Link
        to={`/apps/${app.name}`}
        className="absolute right-2 top-2 inline-flex size-8 items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-white/10 dark:hover:text-white"
        aria-label={`Manage ${app.name}`}
        title="Manage"
      >
        <Icon name="more" />
      </Link>
    </li>
  );
}

function AppGrid() {
  const { can } = useSession();
  const { data, error } = useData(() => api.get<{ apps: InstalledApp[] }>("/apps"), [], { refreshMs: 10000, live: ["containers", "jobs"] });
  return (
    <section aria-labelledby="apps-heading">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 id="apps-heading" className="text-base font-semibold">
          Your apps
        </h2>
        <Link to="/apps" className="text-sm font-medium text-brand-700 hover:underline dark:text-brand-500">
          Manage apps
        </Link>
      </div>
      {!data && (error ? <p className={`text-sm ${muted}`}>{error}</p> : <Spinner />)}
      {data && data.apps.length === 0 && (
        <EmptyState
          title="No apps yet"
          action={
            <Link to="/apps/store" className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-brand-700 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-brand-800">
              <Icon name="store" className="size-4" />
              Browse the app store
            </Link>
          }
        >
          Install apps from verified catalogs. Each app shows what it may access before you install it.
        </EmptyState>
      )}
      {data && data.apps.length > 0 && (
        <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 2xl:grid-cols-5">
          {data.apps.map((a) => (
            <AppTile key={a.name} app={a} />
          ))}
          <li>
            <Link
              to="/apps/store"
              className="flex h-full min-h-36 flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 px-3 py-4 text-center text-sm font-medium text-slate-600 hover:border-brand-600 hover:text-brand-700 dark:border-white/15 dark:text-slate-400 dark:hover:border-brand-500 dark:hover:text-brand-500"
            >
              <span className="mb-2 inline-flex size-14 items-center justify-center rounded-2xl bg-slate-100 dark:bg-white/5" aria-hidden="true">
                <Icon name="plus" className="size-6" />
              </span>
              {can("apps.manage") ? "Add an app" : "App store"}
            </Link>
          </li>
        </ul>
      )}
    </section>
  );
}

// ---- attention and activity ----

interface Issue {
  key: string;
  tone: "red" | "amber" | "blue";
  title: string;
  detail?: string;
  to: string;
}

/** collectIssues turns the readings into one list of things to look at, most severe first. */
export function collectIssues(input: {
  alerts?: AlertItem[];
  services?: ServiceCheck[];
  jobs?: Job[];
  apps?: InstalledApp[];
  findings?: SecurityOverview["findings"];
}): Issue[] {
  const out: Issue[] = [];
  // Security findings about updates repeat the app list below; info findings are not problems.
  input.findings
    ?.filter((f) => f.severity !== "info" && f.area !== "updates")
    .forEach((f, i) => out.push({ key: `sec-${i}`, tone: f.severity === "critical" ? "red" : "amber", title: f.title, detail: `Security · ${f.area}`, to: f.link || "/security" }));
  for (const a of input.alerts ?? []) out.push({ key: `alert-${a.id}`, tone: a.severity === "critical" ? "red" : "amber", title: a.title, detail: a.body, to: "/alerts" });
  for (const s of input.services ?? []) if (s.status === "down") out.push({ key: `svc-${s.name}`, tone: "red", title: `${s.label} is down`, detail: s.detail, to: "/monitoring" });
  for (const j of input.jobs ?? []) if (j.needs_attention) out.push({ key: `job-${j.id}`, tone: "red", title: `${jobTitle(j.kind)} (job #${j.id}) needs attention`, detail: "A rollback failed; check the job.", to: `/jobs/${j.id}` });
  for (const a of input.apps ?? []) if (a.status === "failed") out.push({ key: `app-${a.name}`, tone: "red", title: `${a.name} failed`, detail: a.status_message, to: `/apps/${a.name}` });
  for (const a of input.apps ?? []) if (a.update_available) out.push({ key: `upd-${a.name}`, tone: "blue", title: `Update for ${a.name}`, detail: `${a.version} → ${a.latest_version}`, to: `/apps/${a.name}` });
  const rank = { red: 0, amber: 1, blue: 2 };
  return out.sort((a, b) => rank[a.tone] - rank[b.tone]);
}

const issueStyle = {
  red: { icon: "warning", cls: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300" },
  amber: { icon: "warning", cls: "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300" },
  blue: { icon: "info", cls: "bg-sky-50 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300" },
} as const;

function useIssues() {
  const { can } = useSession();
  const alerts = useData(() => (can("alerts.read") ? api.get<{ alerts: AlertItem[] }>("/alerts?state=firing") : Promise.resolve({ alerts: [] })), [], { refreshMs: 15000, live: ["alerts"] });
  const services = useData(() => (can("system.read") ? api.get<{ services: ServiceCheck[] }>("/health/services") : Promise.resolve({ services: [] })), [], { refreshMs: 15000 });
  const jobs = useData(() => (can("jobs.read") ? api.get<{ jobs: Job[] }>("/jobs?limit=50") : Promise.resolve({ jobs: [] })), [], {
    refreshMs: 3000,
    shouldPoll: (d) => d.jobs.some((j) => ACTIVE_JOB_STATES.includes(j.state)),
    live: ["jobs"],
  });
  const apps = useData(() => (can("apps.read") ? api.get<{ apps: InstalledApp[] }>("/apps") : Promise.resolve({ apps: [] })), [], { refreshMs: 15000, live: ["jobs"] });
  const security = useData(() => (can("security.read") ? api.get<SecurityOverview>("/security/overview") : Promise.resolve({ findings: [] as SecurityOverview["findings"] })), [], {
    refreshMs: 60000,
  });
  // A source that fails to load counts as empty rather than hiding the rest.
  const loaded = [alerts, services, jobs, apps, security].every((d) => d.data || d.error);
  const issues = collectIssues({
    alerts: alerts.data?.alerts,
    services: services.data?.services,
    jobs: jobs.data?.jobs,
    apps: apps.data?.apps,
    findings: security.data?.findings,
  });
  // Never claim that all is well when a check could not run.
  const failed = [alerts, services, jobs, apps, security].filter((d) => d.error).map((d) => d.error);
  if (failed.length > 0) issues.push({ key: "unavailable", tone: "amber", title: "Some checks could not run", detail: failed.join(" · "), to: "/monitoring" });
  return { loaded, issues, jobs: jobs.data?.jobs ?? [] };
}

function Attention({ issues, loaded }: { issues: Issue[]; loaded: boolean }) {
  return (
    <Card title="Needs attention">
      {!loaded && <Spinner />}
      {loaded && issues.length === 0 && (
        <div className="flex items-center gap-3 text-sm">
          <span className="inline-flex size-9 items-center justify-center rounded-full bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300" aria-hidden="true">
            <Icon name="check" className="size-5" />
          </span>
          <span>
            <span className="block font-medium">Everything is running smoothly</span>
            <span className={muted}>No alerts, failures or pending updates.</span>
          </span>
        </div>
      )}
      {loaded && issues.length > 0 && (
        <ul className="-mx-2 space-y-1">
          {issues.slice(0, 6).map((i) => (
            <li key={i.key}>
              <Link to={i.to} className="flex items-start gap-3 rounded-lg px-2 py-2 hover:bg-slate-50 dark:hover:bg-white/5">
                <span className={`mt-0.5 inline-flex size-7 items-center justify-center rounded-lg ${issueStyle[i.tone].cls}`} aria-hidden="true">
                  <Icon name={issueStyle[i.tone].icon} className="size-4" />
                </span>
                <span className="min-w-0 text-sm">
                  <span className="block font-medium">{i.title}</span>
                  {i.detail && <span className={`block truncate text-xs ${muted}`}>{i.detail}</span>}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function Activity({ jobs: all }: { jobs: Job[] }) {
  const jobs = all.filter((j) => !isHousekeeping(j.kind));
  return (
    <Card
      title="Recent activity"
      actions={
        <Link to="/jobs" className="text-sm font-medium text-brand-700 hover:underline dark:text-brand-500">
          All jobs
        </Link>
      }
    >
      {jobs.length === 0 ? (
        <p className={`text-sm ${muted}`}>No deployments, backups or other tasks yet.</p>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-white/5">
          {jobs.slice(0, 6).map((j) => (
            <li key={j.id} className="flex items-center justify-between gap-3 py-2 text-sm">
              <span className="min-w-0">
                <Link to={`/jobs/${j.id}`} className="block truncate font-medium hover:underline">
                  {jobTitle(j.kind)}
                </Link>
                <span className={`text-xs ${muted}`}>
                  #{j.id} · {formatRelative(j.created_at)}
                </span>
              </span>
              <JobStateBadge state={j.state} />
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** HomePage is the start page: system at a glance, the apps, and what needs a look (ADR-0033). */
export function HomePage() {
  const session = useCurrentSession();
  const { can } = useSession();
  const { loaded, issues, jobs } = useIssues();
  const now = new Date();
  const name = session.user.display_name || session.user.username;
  const red = issues.filter((i) => i.tone !== "blue").length;
  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className={`text-sm ${muted}`}>{now.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" })}</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight sm:text-3xl">
            {greeting(now.getHours())}, {name}
          </h1>
        </div>
        {loaded && (
          <Link
            to={red > 0 ? issues[0]!.to : "/monitoring"}
            className={`inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-medium ring-1 ring-inset ${
              red > 0
                ? "bg-amber-50 text-amber-900 ring-amber-600/25 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-500/25"
                : "bg-emerald-50 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-500/25"
            }`}
          >
            <span className={`size-2 rounded-full ${red > 0 ? "bg-amber-500" : "bg-emerald-500"}`} aria-hidden="true" />
            {red > 0 ? `${red} ${red === 1 ? "issue needs" : "issues need"} attention` : "All systems normal"}
          </Link>
        )}
      </header>

      {can("system.read") && <SystemWidgets />}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">{can("apps.read") ? <AppGrid /> : <Card title="Apps">Your role cannot see apps.</Card>}</div>
        <div className="space-y-6">
          <Attention issues={issues} loaded={loaded} />
          {can("jobs.read") && <Activity jobs={jobs} />}
        </div>
      </div>
    </div>
  );
}
