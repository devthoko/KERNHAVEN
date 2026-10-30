import { StepUpDialog } from "./StepUp";
import { useEffect, useState, type ReactNode } from "react";
import { roleLabel } from "../lib/format";
import { currentTab, groupLabels, visibleAreas, type Area } from "../lib/navigation";
import { Link, useRouter } from "../lib/router";
import { useCurrentSession, useSession } from "../lib/session";
import { Icon } from "./Icon";
import { Avatar } from "./ui";

function Brand() {
  return (
    <Link to="/" className="flex items-center gap-2.5 rounded-md text-[15px] font-semibold tracking-tight">
      <img src="/favicon.svg" alt="" className="size-8" />
      <span>Kernhaven</span>
    </Link>
  );
}

/** Sidebar lists the areas by group; an area links to its first page (ADR-0033). */
function Sidebar({ areas, current, onNavigate }: { areas: Area[]; current: Area | null; onNavigate?: () => void }) {
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
                        ? "bg-brand-50 text-brand-800 dark:bg-brand-500/15 dark:text-brand-100"
                        : "text-slate-700 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-white/5 dark:hover:text-white"
                    }`}
                  >
                    <Icon
                      name={a.icon}
                      className={`size-[18px] ${active ? "text-brand-700 dark:text-brand-500" : "text-slate-500 group-hover:text-slate-700 dark:text-slate-400 dark:group-hover:text-slate-200"}`}
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

function UserPanel({ onNavigate }: { onNavigate?: () => void }) {
  const session = useCurrentSession();
  const { logout } = useSession();
  const [busy, setBusy] = useState(false);
  const user = session.user;
  const name = user.display_name || user.username;
  const signOut = async () => {
    setBusy(true);
    try {
      await logout();
    } finally {
      setBusy(false);
    }
  };
  const iconButton =
    "inline-flex size-9 items-center justify-center rounded-lg text-slate-600 hover:bg-slate-100 hover:text-slate-900 disabled:opacity-50 dark:text-slate-400 dark:hover:bg-white/5 dark:hover:text-white";
  return (
    <div className="flex items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 p-2.5 dark:border-white/10 dark:bg-white/5">
      <Avatar name={name} className="size-9 text-sm" />
      <div className="min-w-0 flex-1 text-sm leading-tight">
        <p className="truncate font-medium" title={user.username}>
          {name}
        </p>
        <p className="truncate text-xs text-slate-600 dark:text-slate-400">{roleLabel(user.role)}</p>
      </div>
      <Link to="/account" onClick={onNavigate} className={iconButton} aria-label="Account" title="Account">
        <Icon name="settings" className="size-[18px]" />
      </Link>
      <button type="button" className={iconButton} onClick={signOut} disabled={busy} aria-busy={busy || undefined} aria-label="Sign out" title="Sign out">
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

export function Layout({ children }: { children: ReactNode }) {
  const { can } = useSession();
  const { path } = useRouter();
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => setMenuOpen(false), [path]);

  const areas = visibleAreas(can);
  const here = currentTab(areas, path);

  return (
    <div className="min-h-screen md:flex">
      <StepUpDialog />
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2 dark:focus:bg-slate-900">
        Skip to content
      </a>

      {/* Desktop sidebar */}
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-slate-200 bg-white md:flex dark:border-white/10 dark:bg-slate-900">
        <div className="px-5 pb-4 pt-5">
          <Brand />
        </div>
        <nav aria-label="Main" className="flex min-h-0 flex-1 flex-col justify-between gap-6 overflow-y-auto px-3 pb-3">
          <Sidebar areas={areas} current={here?.area ?? null} />
          <UserPanel />
        </nav>
      </aside>

      {/* Mobile top bar and drawer */}
      <div className="sticky top-0 z-30 flex items-center justify-between border-b border-slate-200 bg-white/90 px-4 py-2.5 backdrop-blur md:hidden dark:border-white/10 dark:bg-slate-900/90">
        <Brand />
        <button
          type="button"
          aria-expanded={menuOpen}
          aria-controls="mobile-nav"
          onClick={() => setMenuOpen((o) => !o)}
          className="inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-white/5"
        >
          <Icon name={menuOpen ? "close" : "menu"} />
          {menuOpen ? "Close" : "Menu"}
        </button>
      </div>
      {menuOpen && (
        <nav id="mobile-nav" aria-label="Main" className="border-b border-slate-200 bg-white px-3 py-4 md:hidden dark:border-white/10 dark:bg-slate-900">
          <Sidebar areas={areas} current={here?.area ?? null} onNavigate={() => setMenuOpen(false)} />
          <div className="mt-6">
            <UserPanel onNavigate={() => setMenuOpen(false)} />
          </div>
        </nav>
      )}

      <main id="main" className="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-10 lg:py-8">
        <div className="mx-auto max-w-7xl">
          {here && <AreaTabs area={here.area} current={here.tab.to} />}
          {children}
        </div>
      </main>
    </div>
  );
}
