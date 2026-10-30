import { StepUpDialog } from "./StepUp";
import { useEffect, useState, type ReactNode } from "react";
import { roleLabel } from "../lib/format";
import { currentTab, groupLabels, visibleAreas, type Area } from "../lib/navigation";
import { Link, useRouter } from "../lib/router";
import { useCurrentSession, useSession } from "../lib/session";
import { StatusProvider, useStatus, type Issue } from "../lib/status";
import type { Theme } from "../lib/types";
import { CommandPalette } from "./CommandPalette";
import { Icon, type IconName } from "./Icon";
import { Popover } from "./Popover";
import { Avatar } from "./ui";

function Brand() {
  return (
    <Link to="/" className="flex items-center gap-2.5 rounded-md text-[15px] font-semibold tracking-tight">
      <img src="/favicon.svg" alt="" className="size-8" />
      <span>Kernhaven</span>
    </Link>
  );
}

/** AreaList lists the areas by group; an area links to its first page (ADR-0033). */
export function AreaList({ areas, current, onNavigate }: { areas: Area[]; current: Area | null; onNavigate?: () => void }) {
  const groups = (["main", "system", "admin"] as const).map((g) => ({ g, items: areas.filter((a) => a.group === g) })).filter((x) => x.items.length > 0);
  return (
    <div className="space-y-6">
      {groups.map(({ g, items }) => (
        <div key={g}>
          {groupLabels[g] && <p className="mb-1.5 px-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">{groupLabels[g]}</p>}
          <ul className="space-y-0.5">
            {items.map((a) => {
              const active = current?.label === a.label;
              return (
                <li key={a.label}>
                  <Link
                    to={a.tabs[0]?.to ?? "/"}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={`group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors motion-reduce:transition-none ${
                      active
                        ? "bg-white text-slate-900 shadow-sm ring-1 ring-slate-200 dark:bg-white/10 dark:text-white dark:ring-white/10"
                        : "text-slate-600 hover:bg-white/70 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-white/5 dark:hover:text-white"
                    }`}
                  >
                    <Icon
                      name={a.icon}
                      className={`size-[18px] ${active ? "text-brand-700 dark:text-brand-500" : "text-slate-500 group-hover:text-slate-700 dark:text-slate-500 dark:group-hover:text-slate-200"}`}
                    />
                    {a.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </div>
  );
}

const themes: { value: Theme; label: string; icon: IconName }[] = [
  { value: "light", label: "Light", icon: "sun" },
  { value: "dark", label: "Dark", icon: "moon" },
  { value: "system", label: "System", icon: "settings" },
];

function useSignOut() {
  const { logout } = useSession();
  const [busy, setBusy] = useState(false);
  const signOut = async () => {
    setBusy(true);
    try {
      await logout();
    } finally {
      setBusy(false);
    }
  };
  return { busy, signOut };
}

function AccountMenu() {
  const session = useCurrentSession();
  const { theme, setTheme } = useSession();
  const { busy, signOut } = useSignOut();
  const name = session.user.display_name || session.user.username;
  const item = "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium hover:bg-slate-100 dark:hover:bg-white/10";
  return (
    <Popover label="Account menu" width="sm:w-72" trigger={<Avatar name={name} className="size-9 text-sm ring-2 ring-white/70 dark:ring-white/10" />}>
      {(close) => (
        <>
          <div className="flex items-center gap-3 px-3 py-2.5">
            <Avatar name={name} className="size-10 text-sm" />
            <div className="min-w-0 text-sm leading-tight">
              <p className="truncate font-semibold">{name}</p>
              <p className="truncate text-xs text-slate-600 dark:text-slate-400">
                {session.user.username} · {roleLabel(session.user.role)}
              </p>
            </div>
          </div>
          <div className="my-1 border-t border-slate-100 dark:border-white/10" />
          <Link to="/account" onClick={close} className={item}>
            <Icon name="settings" className="size-[18px] text-slate-500" />
            Account
          </Link>
          <div className="px-3 py-2">
            <p id="theme-label" className="mb-1.5 text-xs font-medium text-slate-600 dark:text-slate-400">
              Theme
            </p>
            <div role="group" aria-labelledby="theme-label" className="grid grid-cols-3 gap-1 rounded-lg bg-slate-100 p-1 dark:bg-white/5">
              {themes.map((t) => (
                <button
                  key={t.value}
                  type="button"
                  aria-pressed={theme === t.value}
                  onClick={() => void setTheme(t.value)}
                  className={`inline-flex items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-medium ${
                    theme === t.value ? "bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-white" : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
                  }`}
                >
                  <Icon name={t.icon} className="size-3.5" />
                  {t.label}
                </button>
              ))}
            </div>
          </div>
          <div className="my-1 border-t border-slate-100 dark:border-white/10" />
          <button type="button" className={`${item} text-red-700 dark:text-red-400`} onClick={signOut} disabled={busy} aria-busy={busy || undefined}>
            <Icon name="logout" className="size-[18px]" />
            Sign out
          </button>
        </>
      )}
    </Popover>
  );
}

export const issueStyle = {
  red: { icon: "warning", cls: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300" },
  amber: { icon: "warning", cls: "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300" },
  blue: { icon: "info", cls: "bg-sky-50 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300" },
} as const;

/** IssueList shows what needs a look, each line linking to where it is fixed. */
export function IssueList({ issues, onNavigate, max = 6 }: { issues: Issue[]; onNavigate?: () => void; max?: number }) {
  return (
    <ul className="space-y-0.5">
      {issues.slice(0, max).map((i) => (
        <li key={i.key}>
          <Link to={i.to} onClick={onNavigate} className="flex items-start gap-3 rounded-lg px-2 py-2 hover:bg-slate-100/80 dark:hover:bg-white/5">
            <span className={`mt-0.5 inline-flex size-7 shrink-0 items-center justify-center rounded-lg ${issueStyle[i.tone].cls}`} aria-hidden="true">
              <Icon name={issueStyle[i.tone].icon} className="size-4" />
            </span>
            <span className="min-w-0 text-sm">
              <span className="block font-medium">{i.title}</span>
              {i.detail && <span className="block truncate text-xs text-slate-600 dark:text-slate-400">{i.detail}</span>}
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

function Notifications() {
  const { issues, problems, loaded } = useStatus();
  const { can } = useSession();
  return (
    <Popover
      label={problems > 0 ? `Notifications (${problems} need attention)` : "Notifications"}
      width="sm:w-96"
      className="relative size-9 text-slate-600 hover:bg-black/5 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-white/10 dark:hover:text-white"
      trigger={
        <>
          <Icon name="bell" />
          {problems > 0 && (
            <span className="absolute right-1 top-1 inline-flex min-w-4 items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-semibold leading-4 text-white" aria-hidden="true">
              {problems > 9 ? "9+" : problems}
            </span>
          )}
        </>
      }
    >
      {(close) => (
        <div>
          <p className="px-2 pb-2 pt-1 text-sm font-semibold">Notifications</p>
          {!loaded && <p className="px-2 py-4 text-sm text-slate-600 dark:text-slate-400">Checking…</p>}
          {loaded && issues.length === 0 && (
            <div className="flex flex-col items-center gap-2 px-2 py-8 text-center text-sm text-slate-600 dark:text-slate-400">
              <span className="inline-flex size-10 items-center justify-center rounded-full bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300" aria-hidden="true">
                <Icon name="check" />
              </span>
              You are all caught up.
            </div>
          )}
          {loaded && issues.length > 0 && <IssueList issues={issues} onNavigate={close} max={8} />}
          {can("alerts.read") && (
            <div className="mt-1 border-t border-slate-100 px-2 pt-2 dark:border-white/10">
              <Link to="/alerts" onClick={close} className="text-sm font-medium text-brand-700 hover:underline dark:text-brand-500">
                Alerts and notification channels
              </Link>
            </div>
          )}
        </div>
      )}
    </Popover>
  );
}

function SearchButton({ onOpen }: { onOpen: () => void }) {
  const mac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
  return (
    <>
      <button
        type="button"
        onClick={onOpen}
        className="hidden h-9 w-full max-w-md items-center gap-2 rounded-xl border border-slate-200 bg-white/70 px-3 text-sm text-slate-600 shadow-sm backdrop-blur hover:border-slate-300 hover:text-slate-900 sm:flex dark:border-white/10 dark:bg-white/5 dark:text-slate-400 dark:hover:text-white"
      >
        <Icon name="search" className="size-4" />
        <span className="flex-1 text-left">Search or jump to…</span>
        <kbd className="rounded-md border border-slate-200 bg-white px-1.5 font-sans text-[11px] text-slate-500 dark:border-white/15 dark:bg-transparent">{mac ? "⌘K" : "Ctrl K"}</kbd>
      </button>
      <button
        type="button"
        onClick={onOpen}
        aria-label="Search"
        className="inline-flex size-9 items-center justify-center rounded-full text-slate-600 hover:bg-black/5 sm:hidden dark:text-slate-300 dark:hover:bg-white/10"
      >
        <Icon name="search" />
      </button>
    </>
  );
}

function MobileUser({ onNavigate }: { onNavigate: () => void }) {
  const session = useCurrentSession();
  const { busy, signOut } = useSignOut();
  const name = session.user.display_name || session.user.username;
  const iconButton = "inline-flex size-9 items-center justify-center rounded-lg text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-white/10";
  return (
    <div className="flex items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 p-2.5 dark:border-white/10 dark:bg-white/5">
      <Avatar name={name} className="size-9 text-sm" />
      <div className="min-w-0 flex-1 text-sm leading-tight">
        <p className="truncate font-medium">{name}</p>
        <p className="truncate text-xs text-slate-600 dark:text-slate-400">{roleLabel(session.user.role)}</p>
      </div>
      <Link to="/account" onClick={onNavigate} className={iconButton} aria-label="Account" title="Account">
        <Icon name="settings" className="size-[18px]" />
      </Link>
      <button type="button" className={iconButton} onClick={signOut} disabled={busy} aria-label="Sign out" title="Sign out">
        <Icon name="logout" className="size-[18px]" />
      </button>
    </div>
  );
}

/** AreaTabs shows the pages of the current area when it has more than one. */
function AreaTabs({ area, current }: { area: Area; current: string }) {
  if (area.tabs.length < 2) return null;
  return (
    // The border sits on the list, so the active tab's underline overlaps it
    // without overflowing the scroll container.
    <nav aria-label={`${area.label} pages`} className="-mx-4 mb-6 overflow-x-auto overflow-y-hidden px-4 sm:mx-0 sm:px-0">
      <ul className="flex min-w-max gap-6 border-b border-slate-200 dark:border-white/10">
        {area.tabs.map((t) => {
          const active = t.to === current;
          return (
            <li key={t.to}>
              <Link
                to={t.to}
                aria-current={active ? "page" : undefined}
                className={`-mb-px inline-block whitespace-nowrap border-b-2 pb-3 pt-1 text-sm font-medium ${
                  active
                    ? "border-brand-600 text-slate-900 dark:border-brand-500 dark:text-white"
                    : "border-transparent text-slate-600 hover:border-slate-300 hover:text-slate-900 dark:text-slate-400 dark:hover:border-slate-600 dark:hover:text-white"
                }`}
              >
                {t.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

/**
 * Layout is the app shell (ADR-0035). Every page has the top bar with
 * search, notifications and the account menu. Home is a desktop over a
 * coloured background and brings its own area launcher; the other pages
 * are the management view with the sidebar and area tabs.
 */
export function Layout({ children }: { children: ReactNode }) {
  return (
    <StatusProvider>
      <Shell>{children}</Shell>
    </StatusProvider>
  );
}

function Shell({ children }: { children: ReactNode }) {
  const { can } = useSession();
  const { path } = useRouter();
  const [menuOpen, setMenuOpen] = useState(false);
  const [palette, setPalette] = useState(false);

  useEffect(() => setMenuOpen(false), [path]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      }
    };
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, []);

  const areas = visibleAreas(can);
  const here = currentTab(areas, path);
  const home = path === "/";

  return (
    <div className={`min-h-screen ${home ? "" : "md:flex"}`}>
      {home && <div className="kh-wallpaper fixed inset-0 -z-10" aria-hidden="true" />}
      <StepUpDialog />
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2 dark:focus:bg-slate-900">
        Skip to content
      </a>

      {!home && (
        <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-slate-200 bg-slate-50 md:flex dark:border-white/10 dark:bg-slate-950">
          <div className="px-5 pb-5 pt-4">
            <Brand />
          </div>
          <nav aria-label="Main" className="min-h-0 flex-1 overflow-y-auto px-3 pb-4">
            <AreaList areas={areas} current={here?.area ?? null} />
          </nav>
        </aside>
      )}

      <div className="min-w-0 flex-1">
        <header
          className={`sticky top-0 z-30 flex h-16 items-center gap-3 px-4 sm:px-6 lg:px-8 ${
            home ? "bg-transparent" : "border-b border-slate-200 bg-white/80 backdrop-blur dark:border-white/10 dark:bg-slate-900/80"
          }`}
        >
          <div className={home ? "" : "md:hidden"}>
            <Brand />
          </div>
          <div className="flex flex-1 justify-end sm:justify-center">
            <SearchButton onOpen={() => setPalette(true)} />
          </div>
          <div className="flex items-center gap-1.5">
            <Notifications />
            <div className="hidden md:block">
              <AccountMenu />
            </div>
            <button
              type="button"
              aria-expanded={menuOpen}
              aria-controls="mobile-nav"
              onClick={() => setMenuOpen((o) => !o)}
              className="inline-flex items-center gap-2 rounded-lg px-2.5 py-2 text-sm font-medium text-slate-700 hover:bg-black/5 md:hidden dark:text-slate-200 dark:hover:bg-white/10"
            >
              <Icon name={menuOpen ? "close" : "menu"} />
              {menuOpen ? "Close" : "Menu"}
            </button>
          </div>
        </header>

        {menuOpen && (
          <nav id="mobile-nav" aria-label="Main" className="border-b border-slate-200 bg-white px-3 py-4 md:hidden dark:border-white/10 dark:bg-slate-900">
            <AreaList areas={areas} current={here?.area ?? null} onNavigate={() => setMenuOpen(false)} />
            <div className="mt-6">
              <MobileUser onNavigate={() => setMenuOpen(false)} />
            </div>
          </nav>
        )}

        <main id="main" className={`min-w-0 px-4 sm:px-6 lg:px-8 ${home ? "pb-10 pt-2" : "py-6 lg:py-8"}`}>
          <div className="mx-auto max-w-7xl">
            {!home && here && <AreaTabs area={here.area} current={here.tab.to} />}
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
