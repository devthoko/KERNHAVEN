import { useEffect, useId, useMemo, useRef, useState } from "react";
import { visibleAreas } from "../lib/navigation";
import { useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import { useStatus } from "../lib/status";
import type { InstalledApp, Permission } from "../lib/types";
import { webURL } from "../pages/AppsPage";
import { Icon, type IconName } from "./Icon";
import { AppIcon } from "./ui";

export interface Command {
  id: string;
  group: "Pages" | "Apps" | "Actions";
  label: string;
  icon?: IconName;
  app?: string;
  keywords?: string;
  run: () => void;
}

/** filterCommands keeps the commands that contain every word of the query, in order of the list. */
export function filterCommands(list: Command[], query: string): Command[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return list;
  return list.filter((c) => {
    const text = `${c.label} ${c.group} ${c.keywords ?? ""}`.toLowerCase();
    return words.every((w) => text.includes(w));
  });
}

function appURL(a: InstalledApp): string | null {
  if (a.status !== "deployed") return null;
  return a.url || (a.web_port > 0 ? webURL(a.web_port) : null);
}

function useCommands(): Command[] {
  const { can, logout, setTheme, theme } = useSession();
  const { navigate } = useRouter();
  const { apps } = useStatus();
  return useMemo(() => {
    const go = (to: string) => () => navigate(to);
    const out: Command[] = [];
    for (const area of visibleAreas(can)) {
      for (const tab of area.tabs) {
        const label = tab.label === area.label || area.tabs.length === 1 ? area.label : `${area.label} › ${tab.label}`;
        out.push({ id: `page:${tab.to}`, group: "Pages", label, icon: area.icon, run: go(tab.to) });
      }
    }
    for (const a of apps ?? []) {
      const url = appURL(a);
      if (url) out.push({ id: `open:${a.name}`, group: "Apps", label: `Open ${a.name}`, app: a.name, keywords: a.app_name, run: () => window.open(url, "_blank", "noopener,noreferrer") });
      out.push({ id: `manage:${a.name}`, group: "Apps", label: `Manage ${a.name}`, app: a.name, keywords: a.app_name, run: go(`/apps/${a.name}`) });
    }
    const actions: [string, IconName, string, Permission | null][] = [
      ["Install an app", "store", "/apps/store", "apps.manage"],
      ["New container", "box", "/containers/new", "containers.manage"],
      ["New stack", "box", "/stacks/new", "containers.manage"],
      ["Account settings", "settings", "/account", null],
    ];
    for (const [label, icon, to, perm] of actions) if (!perm || can(perm)) out.push({ id: `do:${to}`, group: "Actions", label, icon, run: go(to) });
    const dark = theme === "dark" || (theme === "system" && document.documentElement.classList.contains("dark"));
    out.push({ id: "do:theme", group: "Actions", label: dark ? "Switch to light theme" : "Switch to dark theme", icon: dark ? "sun" : "moon", keywords: "appearance mode", run: () => void setTheme(dark ? "light" : "dark") });
    out.push({ id: "do:logout", group: "Actions", label: "Sign out", icon: "logout", keywords: "log out", run: () => void logout() });
    return out;
  }, [can, navigate, apps, logout, setTheme, theme]);
}

/**
 * CommandPalette finds pages, apps and actions by typing (Ctrl+K or ⌘K).
 * It follows the ARIA combobox pattern: the input keeps focus, arrow keys
 * move the active option, Enter runs it.
 */
export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const listId = useId();
  const commands = useCommands();
  // Group order, so arrow keys move through the list as it is shown.
  const order = { Pages: 0, Apps: 1, Actions: 2 };
  const results = [...filterCommands(commands, query)]
    .sort((a, b) => order[a.group] - order[b.group])
    .slice(0, 50);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      setQuery("");
      setActive(0);
      d.showModal();
      input.current?.focus();
    }
    if (!open && d.open) d.close();
  }, [open]);
  useEffect(() => setActive(0), [query]);
  useEffect(() => {
    document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [active, listId]);

  const run = (c: Command | undefined) => {
    if (!c) return;
    onClose();
    c.run();
  };

  return (
    <dialog
      ref={ref}
      aria-label="Quick find"
      onClose={onClose}
      onClick={(e) => e.target === ref.current && onClose()}
      className="mx-auto mt-[12vh] w-[min(40rem,calc(100vw-2rem))] overflow-hidden rounded-2xl border border-slate-200 bg-white p-0 text-slate-900 shadow-2xl backdrop:bg-slate-950/40 backdrop:backdrop-blur-sm dark:border-white/10 dark:bg-slate-900 dark:text-slate-100"
    >
      {open && (
        <div>
          <div className="flex items-center gap-3 border-b border-slate-200 px-4 dark:border-white/10">
            <Icon name="search" className="size-5 text-slate-500" />
            <input
              ref={input}
              role="combobox"
              aria-label="Find pages, apps and actions"
              aria-expanded="true"
              aria-controls={listId}
              aria-activedescendant={results[active] ? `${listId}-${active}` : undefined}
              autoComplete="off"
              spellCheck={false}
              value={query}
              placeholder="Search pages, apps and actions…"
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setActive((a) => Math.min(a + 1, results.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setActive((a) => Math.max(a - 1, 0));
                } else if (e.key === "Enter") {
                  e.preventDefault();
                  run(results[active]);
                }
              }}
              className="h-14 w-full bg-transparent text-base outline-none placeholder:text-slate-500"
            />
            <kbd className="hidden rounded-lg border border-slate-200 px-1.5 py-0.5 text-xs text-slate-500 sm:inline dark:border-white/15">Esc</kbd>
          </div>
          {/* Grouped listbox as in the WAI-ARIA practices: group > presentation heading + options. */}
          <div id={listId} role="listbox" aria-label="Results" className="max-h-[50vh] overflow-y-auto p-2">
            {results.length === 0 && (
              <p role="presentation" className="px-3 py-8 text-center text-sm text-slate-600 dark:text-slate-400">
                Nothing matches “{query}”.
              </p>
            )}
            {(["Pages", "Apps", "Actions"] as const).map((group) => {
              const items = results.map((c, i) => ({ c, i })).filter((x) => x.c.group === group);
              if (items.length === 0) return null;
              return (
                <ul key={group} role="group" aria-labelledby={`${listId}-${group}`}>
                  <li role="presentation" id={`${listId}-${group}`} className="px-3 pb-1 pt-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    {group}
                  </li>
                  {items.map(({ c, i }) => (
                    <li
                      key={c.id}
                      id={`${listId}-${i}`}
                      role="option"
                      aria-selected={i === active}
                      onMouseMove={() => setActive(i)}
                      onClick={() => run(c)}
                      className={`flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm ${i === active ? "bg-brand-50 text-brand-800 dark:bg-brand-500/15 dark:text-white" : ""}`}
                    >
                      {c.app ? <AppIcon name={c.app} size="sm" /> : <Icon name={c.icon ?? "chevronRight"} className="size-[18px] text-slate-500 dark:text-slate-400" />}
                      <span className="truncate">{c.label}</span>
                      {i === active && <Icon name="chevronRight" className="ml-auto size-4 opacity-60" />}
                    </li>
                  ))}
                </ul>
              );
            })}
          </div>
        </div>
      )}
    </dialog>
  );
}
