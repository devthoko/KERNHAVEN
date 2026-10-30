import { formatValue } from "../components/Chart";
import { Icon, type IconName } from "../components/Icon";
import { isHousekeeping, jobTitle, JobStateBadge } from "../components/JobBits";
import { IssueList } from "../components/Layout";
import { AppIcon, buttonClass, Card, EmptyState, link, Meter, PageHeader, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { formatBytes, formatRelative } from "../lib/format";
import { Link } from "../lib/router";
import { useCurrentSession, useSession } from "../lib/session";
import { useStatus } from "../lib/status";
import type { FileSystemInfo, HostMetrics, InstalledApp, StorageInventory } from "../lib/types";
import { useData } from "../lib/useData";
import { webURL } from "./AppsPage";

const muted = "text-slate-600 dark:text-slate-400";

export function greeting(hour: number): string {
  if (hour < 5) return "Good evening";
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

/** largestFileSystem picks the file system people care about most: the system root, else the biggest one. */
export function largestFileSystem(inv: StorageInventory): FileSystemInfo | null {
  const all = inv.disks.flatMap((d) => d.file_systems).filter((f) => f.fs_size_bytes > 0);
  return all.find((f) => f.mountpoints.includes("/")) ?? all.sort((a, b) => b.fs_size_bytes - a.fs_size_bytes)[0] ?? null;
}

function Stat({ icon, label, value, percent, detail }: { icon: IconName; label: string; value: string; percent?: number; detail?: string }) {
  return (
    <Card className="min-w-0">
      <p className={`flex items-center gap-2 text-sm font-medium ${muted}`}>
        <Icon name={icon} className="size-4" />
        {label}
      </p>
      <p className="mt-2 truncate text-2xl font-semibold tabular-nums tracking-tight">{value}</p>
      {percent !== undefined && <Meter percent={percent} className="mt-3" />}
      {detail && <p className={`mt-2 truncate text-xs ${muted}`}>{detail}</p>}
    </Card>
  );
}

function SystemStats() {
  const { can } = useSession();
  const host = useData(() => api.get<HostMetrics>("/metrics/host"), [], { refreshMs: 15000 });
  const storage = useData(() => (can("storage.read") ? api.get<StorageInventory>("/storage") : Promise.resolve(null)), [], { refreshMs: 60000 });
  const h = host.data;
  const fs = storage.data ? largestFileSystem(storage.data) : null;
  const grid = "grid grid-cols-2 gap-4 lg:grid-cols-4";
  if (!h) {
    if (!host.error) return <Spinner label="Reading the system" />;
    const none = "No reading yet: the monitor service is not reachable.";
    return (
      <div className={grid}>
        <Stat icon="cpu" label="Processor" value="—" detail={none} />
        <Stat icon="memory" label="Memory" value="—" detail={none} />
        <Stat icon="disk" label="Storage" value="—" detail={none} />
        <Stat icon="network" label="Network" value="—" detail={none} />
      </div>
    );
  }
  const memPct = h.memory.total ? (h.memory_used / h.memory.total) * 100 : 0;
  const rx = h.interfaces.reduce((a, i) => a + i.in, 0);
  const tx = h.interfaces.reduce((a, i) => a + i.out, 0);
  return (
    <section aria-label="System" className={grid}>
      <Stat icon="cpu" label="Processor" value={h.cpu_percent === null ? "—" : formatValue(h.cpu_percent, "percent")} percent={h.cpu_percent ?? 0} detail={`${h.cpus} cores · load ${h.load[0].toFixed(2)}`} />
      <Stat icon="memory" label="Memory" value={`${memPct.toFixed(0)} %`} percent={memPct} detail={`${formatBytes(h.memory_used)} of ${formatBytes(h.memory.total)}`} />
      {fs ? (
        <Stat
          icon="disk"
          label="Storage"
          value={`${Math.round((fs.fs_used_bytes / fs.fs_size_bytes) * 100)} %`}
          percent={(fs.fs_used_bytes / fs.fs_size_bytes) * 100}
          detail={`${formatBytes(fs.fs_available_bytes)} free of ${formatBytes(fs.fs_size_bytes)}`}
        />
      ) : (
        <Stat icon="disk" label="Storage" value="—" detail={can("storage.read") ? "No file system reported" : "Needs storage access"} />
      )}
      <Stat icon="network" label="Network" value={`↓ ${formatValue(rx, "bytes/s")}`} detail={`↑ ${formatValue(tx, "bytes/s")} sent`} />
    </section>
  );
}

// ---- apps ----

function statusOf(app: InstalledApp): { label: string; dot: string } {
  switch (app.status) {
    case "deployed":
      return { label: "Running", dot: "bg-emerald-500" };
    case "deploying":
      return { label: "Starting", dot: "bg-sky-500" };
    case "stopping":
      return { label: "Stopping", dot: "bg-sky-500" };
    case "failed":
      return { label: "Failed", dot: "bg-red-500" };
    case "stopped":
      return { label: "Stopped", dot: "bg-slate-400" };
    default:
      return { label: app.status, dot: "bg-slate-400" };
  }
}

function AppLauncher({ app }: { app: InstalledApp }) {
  const url = app.status === "deployed" ? app.url || (app.web_port > 0 ? webURL(app.web_port) : "") : "";
  const st = statusOf(app);
  const body = (
    <>
      <span className="relative">
        <AppIcon name={app.name} size="lg" />
        <span className={`absolute -bottom-0.5 -right-0.5 size-3.5 rounded-full ring-2 ring-white dark:ring-slate-900 ${st.dot}`} aria-hidden="true" />
      </span>
      <span className="mt-2.5 block max-w-full truncate text-sm font-medium">{app.name}</span>
      <span className={`block text-xs ${muted}`}>{app.update_available ? "Update available" : st.label}</span>
    </>
  );
  const tile =
    "flex flex-col items-center rounded-xl px-2 pb-3 pt-4 text-center transition hover:bg-slate-50 motion-reduce:transition-none dark:hover:bg-white/5";
  return (
    <li className="group relative">
      {url ? (
        // Named by its visible text (WCAG 2.5.3); the hidden words add the action.
        <a href={url} target="_blank" rel="noopener noreferrer" className={tile}>
          <span className="sr-only">Open </span>
          {body}
          <span className="sr-only"> (opens in a new tab)</span>
        </a>
      ) : (
        <Link to={`/apps/${app.name}`} className={tile}>
          {body}
        </Link>
      )}
      <Link
        to={`/apps/${app.name}`}
        className="absolute right-1 top-1 inline-flex size-8 items-center justify-center rounded-full bg-white/80 text-slate-600 opacity-100 shadow-sm backdrop-blur transition hover:text-slate-900 focus-visible:opacity-100 sm:opacity-0 sm:group-hover:opacity-100 dark:bg-slate-800/80 dark:text-slate-300 dark:hover:text-white"
        aria-label={`Manage ${app.name}`}
        title="Manage"
      >
        <Icon name="more" className="size-4" />
      </Link>
    </li>
  );
}

function Apps() {
  const { can } = useSession();
  const { apps, appsError } = useStatus();
  return (
    <Card
      title="Your apps"
      actions={
        <Link to="/apps" className={`text-sm ${link}`}>
          Manage apps
        </Link>
      }
    >
      {!apps && (appsError ? <p className={`text-sm ${muted}`}>{appsError}</p> : <Spinner />)}
      {apps && apps.length === 0 && (
        <EmptyState
          title="No apps yet"
          action={
            <Link to="/apps/store" className={buttonClass("primary")}>
              Browse the app store
            </Link>
          }
        >
          Start with Kernhaven Essentials: passwords, media, file sync and more, each showing what it may access before you install it.
        </EmptyState>
      )}
      {apps && apps.length > 0 && (
        <ul className="-mx-2 grid grid-cols-3 gap-1 sm:grid-cols-4 lg:grid-cols-6">
          {apps.map((a) => (
            <AppLauncher key={a.name} app={a} />
          ))}
          <li>
            <Link to="/apps/store" className="flex flex-col items-center rounded-xl px-2 pb-3 pt-4 text-center text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-white/5">
              <span
                className="inline-flex size-16 items-center justify-center rounded-[20px] border-2 border-dashed border-slate-300 sm:size-[72px] sm:rounded-[22px] dark:border-white/20"
                aria-hidden="true"
              >
                <Icon name="plus" className="size-7" />
              </span>
              <span className="mt-2.5 block text-sm font-medium">{can("apps.manage") ? "Add an app" : "App store"}</span>
              <span className={`block text-xs ${muted}`}>Essentials and more</span>
            </Link>
          </li>
        </ul>
      )}
    </Card>
  );
}

// ---- attention, activity, launcher ----

function Attention() {
  const { issues, loaded } = useStatus();
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
      {loaded && issues.length > 0 && <IssueList issues={issues} />}
    </Card>
  );
}

function Activity() {
  const { jobs: all } = useStatus();
  const jobs = all.filter((j) => !isHousekeeping(j.kind)).slice(0, 5);
  return (
    <Card
      title="Recent activity"
      actions={
        <Link to="/jobs" className={`text-sm ${link}`}>
          All jobs
        </Link>
      }
    >
      {jobs.length === 0 ? (
        <p className={`text-sm ${muted}`}>No deployments, backups or other tasks yet.</p>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-white/5">
          {jobs.map((j) => (
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

/** HomePage shows the server at a glance, the apps as a launcher, and what needs a look (ADR-0035). */
export function HomePage() {
  const session = useCurrentSession();
  const { can } = useSession();
  const { loaded, issues, problems } = useStatus();
  const name = session.user.display_name || session.user.username;
  const now = new Date();
  return (
    <>
      <PageHeader
        title={`${greeting(now.getHours())}, ${name}`}
        description={now.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long", year: "numeric" })}
        actions={
          loaded && (
            <Link
              to={problems > 0 ? issues[0]!.to : "/monitoring"}
              className={`inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-medium ring-1 ring-inset ${
                problems > 0
                  ? "bg-amber-50 text-amber-900 ring-amber-600/25 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-500/25"
                  : "bg-emerald-50 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-500/25"
              }`}
            >
              <span className={`size-2 rounded-full ${problems > 0 ? "bg-amber-500" : "bg-emerald-500"}`} aria-hidden="true" />
              {problems > 0 ? `${problems} ${problems === 1 ? "issue needs" : "issues need"} attention` : "All systems normal"}
            </Link>
          )
        }
      />
      <div className="space-y-6">
        {can("system.read") && <SystemStats />}
        {can("apps.read") && <Apps />}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Attention />
          {can("jobs.read") && <Activity />}
        </div>
      </div>
    </>
  );
}
