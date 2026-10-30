import { useEffect, useState, type ReactNode } from "react";
import { formatValue } from "../components/Chart";
import { Icon, type IconName } from "../components/Icon";
import { isHousekeeping, jobTitle, JobStateBadge } from "../components/JobBits";
import { IssueList } from "../components/Layout";
import { AppIcon, glass, Meter, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { formatBytes, formatRelative } from "../lib/format";
import { visibleAreas } from "../lib/navigation";
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

function GlassCard({ title, icon, action, children, className = "" }: { title: string; icon?: IconName; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section aria-label={title} className={`${glass} p-4 sm:p-5 ${className}`}>
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          {icon && <Icon name={icon} className="size-4 text-slate-500 dark:text-slate-400" />}
          {title}
        </h2>
        {action}
      </div>
      {children}
    </section>
  );
}

// ---- widgets (left column) ----

function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), 15000);
    return () => window.clearInterval(t);
  }, []);
  return (
    <div className={`${glass} px-5 py-4`}>
      <p className="text-4xl font-semibold tabular-nums tracking-tight">{now.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}</p>
      <p className={`mt-1 text-sm ${muted}`}>{now.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" })}</p>
    </div>
  );
}

function Reading({ label, value, percent, detail }: { label: string; value: string; percent?: number; detail?: string }) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2 text-sm">
        <span className={muted}>{label}</span>
        <span className="font-semibold tabular-nums">{value}</span>
      </div>
      {percent !== undefined && <Meter percent={percent} className="mt-1.5" />}
      {detail && <p className={`mt-1 truncate text-xs ${muted}`}>{detail}</p>}
    </div>
  );
}

function SystemWidgets() {
  const { can } = useSession();
  const host = useData(() => api.get<HostMetrics>("/metrics/host"), [], { refreshMs: 15000 });
  const storage = useData(() => (can("storage.read") ? api.get<StorageInventory>("/storage") : Promise.resolve(null)), [], { refreshMs: 60000 });
  const h = host.data;
  const fs = storage.data ? largestFileSystem(storage.data) : null;
  const link = <Link to="/monitoring" className="text-xs font-medium text-brand-700 hover:underline dark:text-brand-500">Details</Link>;
  if (!h) {
    return (
      <GlassCard title="System" icon="cpu" action={link}>
        {host.error ? <p className={`text-sm ${muted}`}>No reading yet: the monitor service is not reachable.</p> : <Spinner label="Reading the system" />}
      </GlassCard>
    );
  }
  const memPct = h.memory.total ? (h.memory_used / h.memory.total) * 100 : 0;
  const rx = h.interfaces.reduce((a, i) => a + i.in, 0);
  const tx = h.interfaces.reduce((a, i) => a + i.out, 0);
  return (
    <>
      <GlassCard title="System" icon="cpu" action={link}>
        <div className="space-y-3">
          <Reading
            label="Processor"
            value={h.cpu_percent === null ? "—" : formatValue(h.cpu_percent, "percent")}
            percent={h.cpu_percent ?? 0}
            detail={`${h.cpus} cores · load ${h.load[0].toFixed(2)}`}
          />
          <Reading label="Memory" value={`${memPct.toFixed(0)} %`} percent={memPct} detail={`${formatBytes(h.memory_used)} of ${formatBytes(h.memory.total)}`} />
        </div>
      </GlassCard>
      {fs && (
        <GlassCard title="Storage" icon="disk">
          <Reading
            label={fs.mountpoints.includes("/") ? "System disk" : fs.mount_name || fs.name}
            value={`${Math.round((fs.fs_used_bytes / fs.fs_size_bytes) * 100)} %`}
            percent={(fs.fs_used_bytes / fs.fs_size_bytes) * 100}
            detail={`${formatBytes(fs.fs_available_bytes)} free of ${formatBytes(fs.fs_size_bytes)}`}
          />
        </GlassCard>
      )}
      <GlassCard title="Network" icon="network">
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div>
            <p className={muted}>Download</p>
            <p className="font-semibold tabular-nums">{formatValue(rx, "bytes/s")}</p>
          </div>
          <div>
            <p className={muted}>Upload</p>
            <p className="font-semibold tabular-nums">{formatValue(tx, "bytes/s")}</p>
          </div>
        </div>
      </GlassCard>
    </>
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
    "flex flex-col items-center rounded-2xl px-2 pb-3 pt-4 text-center transition hover:bg-white/60 motion-reduce:transition-none dark:hover:bg-white/5";
  return (
    <li className="group relative">
      {url ? (
        <a href={url} target="_blank" rel="noopener noreferrer" className={tile} aria-label={`Open ${app.name} (new tab), ${st.label}`}>
          {body}
        </a>
      ) : (
        <Link to={`/apps/${app.name}`} className={tile} aria-label={`${app.name}: ${st.label}`}>
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
    <section aria-labelledby="apps-heading">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 id="apps-heading" className="text-base font-semibold">
          Your apps
        </h2>
        <Link to="/apps" className="text-sm font-medium text-brand-700 hover:underline dark:text-brand-500">
          Manage apps
        </Link>
      </div>
      {!apps && (appsError ? <p className={`text-sm ${muted}`}>{appsError}</p> : <Spinner />)}
      {apps && apps.length === 0 && (
        <div className={`${glass} flex flex-col items-center px-6 py-10 text-center`}>
          <span className="inline-flex size-14 items-center justify-center rounded-2xl bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-500" aria-hidden="true">
            <Icon name="store" className="size-7" />
          </span>
          <p className="mt-4 font-semibold">No apps yet</p>
          <p className={`mt-1 max-w-sm text-sm ${muted}`}>Start with Kernhaven Essentials: passwords, media, file sync and more, each showing what it may access before you install it.</p>
          <Link to="/apps/store" className="mt-5 inline-flex min-h-10 items-center gap-2 rounded-lg bg-brand-700 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-brand-800">
            Browse the app store
          </Link>
        </div>
      )}
      {apps && apps.length > 0 && (
        <ul className="grid grid-cols-3 gap-1 sm:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6">
          {apps.map((a) => (
            <AppLauncher key={a.name} app={a} />
          ))}
          <li>
            <Link to="/apps/store" className="flex flex-col items-center rounded-2xl px-2 pb-3 pt-4 text-center text-slate-600 hover:bg-white/60 dark:text-slate-300 dark:hover:bg-white/5">
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
    </section>
  );
}

// ---- attention, activity, launcher ----

function Attention() {
  const { issues, loaded } = useStatus();
  return (
    <GlassCard title="Needs attention" icon="bell">
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
    </GlassCard>
  );
}

function Activity() {
  const { jobs: all } = useStatus();
  const jobs = all.filter((j) => !isHousekeeping(j.kind)).slice(0, 5);
  return (
    <GlassCard
      title="Recent activity"
      icon="jobs"
      action={
        <Link to="/jobs" className="text-xs font-medium text-brand-700 hover:underline dark:text-brand-500">
          All jobs
        </Link>
      }
    >
      {jobs.length === 0 ? (
        <p className={`text-sm ${muted}`}>No deployments, backups or other tasks yet.</p>
      ) : (
        <ul className="divide-y divide-slate-200/60 dark:divide-white/5">
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
    </GlassCard>
  );
}

/** Launcher is the dock of management areas on the desktop (the main navigation there). */
function Launcher() {
  const { can } = useSession();
  const areas = visibleAreas(can).filter((a) => a.label !== "Home");
  return (
    <nav aria-label="Main" className={`${glass} hidden p-2 md:block`}>
      <ul className="grid grid-cols-5 gap-1 lg:grid-cols-10">
        {areas.map((a) => (
          <li key={a.label}>
            <Link
              to={a.tabs[0]?.to ?? "/"}
              className="flex flex-col items-center gap-1.5 rounded-xl px-1 py-2.5 text-xs font-medium text-slate-700 hover:bg-white/80 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-white/10 dark:hover:text-white"
            >
              <span className="inline-flex size-10 items-center justify-center rounded-xl bg-slate-900/5 text-slate-700 dark:bg-white/10 dark:text-slate-200" aria-hidden="true">
                <Icon name={a.icon} />
              </span>
              {a.label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/** HomePage is the desktop: widgets, apps, what needs a look, and the way into management (ADR-0035). */
export function HomePage() {
  const session = useCurrentSession();
  const { can } = useSession();
  const { loaded, issues, problems } = useStatus();
  const name = session.user.display_name || session.user.username;
  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[18rem_1fr] lg:gap-8">
      <div className="order-2 space-y-4 lg:order-1">
        <Clock />
        {can("system.read") && <SystemWidgets />}
      </div>
      <div className="order-1 min-w-0 space-y-6 lg:order-2">
        <header className="flex flex-wrap items-end justify-between gap-3">
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            {greeting(new Date().getHours())}, {name}
          </h1>
          {loaded && (
            <Link
              to={problems > 0 ? issues[0]!.to : "/monitoring"}
              className={`inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-medium shadow-sm ring-1 ring-inset backdrop-blur ${
                problems > 0
                  ? "bg-amber-50/90 text-amber-900 ring-amber-600/25 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-500/25"
                  : "bg-emerald-50/90 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-500/25"
              }`}
            >
              <span className={`size-2 rounded-full ${problems > 0 ? "bg-amber-500" : "bg-emerald-500"}`} aria-hidden="true" />
              {problems > 0 ? `${problems} ${problems === 1 ? "issue needs" : "issues need"} attention` : "All systems normal"}
            </Link>
          )}
        </header>
        {can("apps.read") && <Apps />}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Attention />
          {can("jobs.read") && <Activity />}
        </div>
        <Launcher />
      </div>
    </div>
  );
}
