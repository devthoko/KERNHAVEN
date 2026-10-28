import { useEffect, useState, type ReactNode } from "react";
import { Link, useRouter } from "../lib/router";
import { useCurrentSession, useSession } from "../lib/session";
import type { Permission } from "../lib/types";
import { roleLabel } from "../lib/format";
import { Button } from "./ui";

const nav: { to: string; label: string; permission?: Permission }[] = [
  { to: "/", label: "Dashboard" },
  { to: "/apps", label: "Apps", permission: "apps.read" },
  { to: "/apps/store", label: "App store", permission: "apps.read" },
  { to: "/stacks", label: "Stacks", permission: "containers.read" },
  { to: "/containers", label: "Containers", permission: "containers.read" },
  { to: "/images", label: "Images", permission: "containers.read" },
  { to: "/volumes", label: "Volumes", permission: "containers.read" },
  { to: "/networks", label: "Networks", permission: "containers.read" },
  { to: "/storage", label: "Storage", permission: "storage.read" },
  { to: "/files", label: "Files", permission: "files.read" },
  { to: "/jobs", label: "Jobs", permission: "jobs.read" },
  { to: "/users", label: "Users", permission: "users.read" },
  { to: "/audit", label: "Audit log", permission: "audit.read" },
  { to: "/account", label: "Account" },
];

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const { path } = useRouter();
  const { can } = useSession();
  const matches = (to: string) => (to === "/" ? path === "/" : path === to || path.startsWith(`${to}/`));
  // Only the most specific entry is current (/apps/store is not also /apps).
  const current = nav.filter((n) => matches(n.to)).sort((a, b) => b.to.length - a.to.length)[0]?.to;
  return (
    <ul className="space-y-1">
      {nav
        .filter((n) => !n.permission || can(n.permission))
        .map((n) => {
          const active = n.to === current;
          return (
            <li key={n.to}>
              <Link
                to={n.to}
                onClick={onNavigate}
                aria-current={active ? "page" : undefined}
                className={`block rounded-md px-3 py-2 text-sm font-medium ${
                  active
                    ? "bg-brand-100 text-brand-800 dark:bg-brand-800 dark:text-white"
                    : "text-slate-700 hover:bg-slate-200 dark:text-slate-300 dark:hover:bg-slate-800"
                }`}
              >
                {n.label}
              </Link>
            </li>
          );
        })}
    </ul>
  );
}

function Brand() {
  return (
    <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight">
      <img src="/favicon.svg" alt="" className="size-7" />
      <span>Kernhaven</span>
    </Link>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const session = useCurrentSession();
  const { logout } = useSession();
  const { path } = useRouter();
  const [menuOpen, setMenuOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => setMenuOpen(false), [path]);

  const user = session.user;
  const signOut = async () => {
    setBusy(true);
    try {
      await logout();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen md:flex">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2 dark:focus:bg-slate-900">
        Skip to content
      </a>

      {/* Desktop sidebar */}
      <aside className="hidden w-60 shrink-0 border-r border-slate-200 bg-white px-4 py-5 md:flex md:flex-col dark:border-slate-800 dark:bg-slate-900">
        <Brand />
        <nav aria-label="Main" className="mt-6 flex-1">
          <NavLinks />
        </nav>
        <div className="border-t border-slate-200 pt-4 text-sm dark:border-slate-800">
          <p className="truncate font-medium" title={user.username}>
            {user.display_name || user.username}
          </p>
          <p className="text-slate-600 dark:text-slate-400">{roleLabel(user.role)}</p>
          <Button variant="secondary" className="mt-3 w-full" onClick={signOut} busy={busy}>
            Sign out
          </Button>
        </div>
      </aside>

      {/* Mobile top bar */}
      <div className="flex items-center justify-between border-b border-slate-200 bg-white px-4 py-3 md:hidden dark:border-slate-800 dark:bg-slate-900">
        <Brand />
        <Button variant="ghost" aria-expanded={menuOpen} aria-controls="mobile-nav" onClick={() => setMenuOpen((o) => !o)}>
          {menuOpen ? "Close" : "Menu"}
        </Button>
      </div>
      {menuOpen && (
        <nav id="mobile-nav" aria-label="Main" className="border-b border-slate-200 bg-white px-4 py-3 md:hidden dark:border-slate-800 dark:bg-slate-900">
          <NavLinks onNavigate={() => setMenuOpen(false)} />
          <div className="mt-3 flex items-center justify-between border-t border-slate-200 pt-3 text-sm dark:border-slate-800">
            <span className="truncate">
              {user.display_name || user.username} · {roleLabel(user.role)}
            </span>
            <Button variant="secondary" onClick={signOut} busy={busy}>
              Sign out
            </Button>
          </div>
        </nav>
      )}

      <main id="main" className="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-10">
        <div className="mx-auto max-w-6xl">{children}</div>
      </main>
    </div>
  );
}
