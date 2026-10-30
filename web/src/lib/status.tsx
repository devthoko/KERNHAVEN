import { createContext, useContext, type ReactNode } from "react";
import { jobTitle } from "../components/JobBits";
import { api } from "./api";
import { useSession } from "./session";
import { ACTIVE_JOB_STATES, type Alert as AlertItem, type InstalledApp, type Job, type SecurityOverview, type ServiceCheck } from "./types";
import { useData } from "./useData";

export interface Issue {
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
  for (const j of input.jobs ?? [])
    if (j.needs_attention) out.push({ key: `job-${j.id}`, tone: "red", title: `${jobTitle(j.kind)} (job #${j.id}) needs attention`, detail: "A rollback failed; check the job.", to: `/jobs/${j.id}` });
  for (const a of input.apps ?? []) if (a.status === "failed") out.push({ key: `app-${a.name}`, tone: "red", title: `${a.name} failed`, detail: a.status_message, to: `/apps/${a.name}` });
  for (const a of input.apps ?? []) if (a.update_available) out.push({ key: `upd-${a.name}`, tone: "blue", title: `Update for ${a.name}`, detail: `${a.version} → ${a.latest_version}`, to: `/apps/${a.name}` });
  const rank = { red: 0, amber: 1, blue: 2 };
  return out.sort((a, b) => rank[a.tone] - rank[b.tone]);
}

interface Status {
  /** Every source answered (or failed). */
  loaded: boolean;
  issues: Issue[];
  /** Issues that are problems, not just news (updates). */
  problems: number;
  jobs: Job[];
  apps: InstalledApp[] | null;
  appsError: string | null;
}

const StatusContext = createContext<Status | null>(null);

/**
 * StatusProvider reads what the home page and the notification bell show,
 * once for both (ADR-0035). Every request goes through the normal,
 * permission-checked API; sources the role may not read count as empty.
 */
export function StatusProvider({ children }: { children: ReactNode }) {
  const { can } = useSession();
  const alerts = useData(() => (can("alerts.read") ? api.get<{ alerts: AlertItem[] }>("/alerts?state=firing") : Promise.resolve({ alerts: [] })), [], {
    refreshMs: 15000,
    live: ["alerts"],
  });
  const services = useData(() => (can("system.read") ? api.get<{ services: ServiceCheck[] }>("/health/services") : Promise.resolve({ services: [] })), [], { refreshMs: 15000 });
  const jobs = useData(() => (can("jobs.read") ? api.get<{ jobs: Job[] }>("/jobs?limit=50") : Promise.resolve({ jobs: [] })), [], {
    refreshMs: 3000,
    shouldPoll: (d) => d.jobs.some((j) => ACTIVE_JOB_STATES.includes(j.state)),
    live: ["jobs"],
  });
  const apps = useData(() => (can("apps.read") ? api.get<{ apps: InstalledApp[] }>("/apps") : Promise.resolve({ apps: [] })), [], {
    refreshMs: 10000,
    live: ["containers", "jobs"],
  });
  const security = useData(
    () => (can("security.read") ? api.get<SecurityOverview>("/security/overview") : Promise.resolve({ findings: [] as SecurityOverview["findings"] })),
    [],
    { refreshMs: 60000 },
  );
  const all = [alerts, services, jobs, apps, security];
  const issues = collectIssues({
    alerts: alerts.data?.alerts,
    services: services.data?.services,
    jobs: jobs.data?.jobs,
    apps: apps.data?.apps,
    findings: security.data?.findings,
  });
  // Never claim that all is well when a check could not run.
  const failed = all.filter((d) => d.error).map((d) => d.error);
  if (failed.length > 0) issues.push({ key: "unavailable", tone: "amber", title: "Some checks could not run", detail: failed.join(" · "), to: "/monitoring" });
  const value: Status = {
    loaded: all.every((d) => d.data || d.error),
    issues,
    problems: issues.filter((i) => i.tone !== "blue").length,
    jobs: jobs.data?.jobs ?? [],
    apps: apps.data?.apps ?? null,
    appsError: apps.error,
  };
  return <StatusContext.Provider value={value}>{children}</StatusContext.Provider>;
}

export function useStatus(): Status {
  const s = useContext(StatusContext);
  if (!s) throw new Error("useStatus outside StatusProvider");
  return s;
}
