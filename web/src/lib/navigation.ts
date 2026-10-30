import type { IconName } from "../components/Icon";
import type { Permission } from "./types";

/**
 * The information architecture of the web UI (ADR-0033): a short sidebar of
 * areas, grouped by what people come to do, and tabs inside an area for its
 * related pages. Each page belongs to exactly one area.
 */
export interface Tab {
  to: string;
  label: string;
  permission?: Permission;
}

export interface Area {
  label: string;
  icon: IconName;
  group: "main" | "system" | "admin";
  /** Pages of the area, in tab order. One page means no tab bar. */
  tabs: Tab[];
}

export const areas: Area[] = [
  { label: "Home", icon: "home", group: "main", tabs: [{ to: "/", label: "Home" }] },
  {
    label: "Apps",
    icon: "apps",
    group: "main",
    tabs: [
      { to: "/apps", label: "Installed", permission: "apps.read" },
      { to: "/apps/store", label: "App store", permission: "apps.read" },
      { to: "/apps/sources", label: "Catalog sources", permission: "apps.read" },
    ],
  },
  { label: "Files", icon: "folder", group: "main", tabs: [{ to: "/files", label: "Files", permission: "files.read" }] },
  { label: "Storage", icon: "disk", group: "main", tabs: [{ to: "/storage", label: "Storage", permission: "storage.read" }] },
  { label: "Backups", icon: "backup", group: "main", tabs: [{ to: "/backups", label: "Backups", permission: "backup.read" }] },
  {
    label: "Monitoring",
    icon: "activity",
    group: "system",
    tabs: [
      { to: "/monitoring", label: "Overview", permission: "system.read" },
      { to: "/alerts", label: "Alerts", permission: "alerts.read" },
    ],
  },
  {
    label: "Docker",
    icon: "box",
    group: "system",
    tabs: [
      { to: "/containers", label: "Containers", permission: "containers.read" },
      { to: "/stacks", label: "Stacks", permission: "containers.read" },
      { to: "/images", label: "Images", permission: "containers.read" },
      { to: "/volumes", label: "Volumes", permission: "containers.read" },
      { to: "/networks", label: "Networks", permission: "containers.read" },
    ],
  },
  {
    label: "Network",
    icon: "globe",
    group: "system",
    tabs: [
      { to: "/proxy", label: "Reverse proxy", permission: "network.read" },
      { to: "/certificates", label: "Certificates", permission: "network.read" },
    ],
  },
  { label: "Jobs", icon: "jobs", group: "system", tabs: [{ to: "/jobs", label: "Jobs", permission: "jobs.read" }] },
  { label: "Users", icon: "users", group: "admin", tabs: [{ to: "/users", label: "Users", permission: "users.read" }] },
  {
    label: "Security",
    icon: "shield",
    group: "admin",
    tabs: [
      { to: "/security", label: "Overview", permission: "security.read" },
      { to: "/audit", label: "Audit log", permission: "audit.read" },
    ],
  },
];

export const groupLabels: Record<Area["group"], string | null> = { main: null, system: "System", admin: "Administration" };

/** pathMatches says whether path is the page at "to" or below it. */
export function pathMatches(to: string, path: string): boolean {
  return to === "/" ? path === "/" : path === to || path.startsWith(`${to}/`);
}

/** visibleAreas keeps the areas with at least one permitted page, and only those pages. */
export function visibleAreas(can: (p: Permission) => boolean): Area[] {
  return areas
    .map((a) => ({ ...a, tabs: a.tabs.filter((t) => !t.permission || can(t.permission)) }))
    .filter((a) => a.tabs.length > 0);
}

/** currentTab finds the area and tab of a path: the most specific matching tab wins (/apps/store is not /apps). */
export function currentTab(list: Area[], path: string): { area: Area; tab: Tab } | null {
  let best: { area: Area; tab: Tab } | null = null;
  for (const area of list) {
    for (const tab of area.tabs) {
      if (pathMatches(tab.to, path) && (!best || tab.to.length > best.tab.to.length)) best = { area, tab };
    }
  }
  return best;
}
