import { Link } from "../lib/router";
import { Icon, type IconName } from "./Icon";
import { useEffect, useId, useRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "danger" | "ghost";

const variants: Record<Variant, string> = {
  primary: "bg-brand-700 text-white shadow-sm hover:bg-brand-800 disabled:bg-brand-700/50",
  secondary:
    "border border-slate-300 bg-white text-slate-800 shadow-sm hover:bg-slate-50 dark:border-white/15 dark:bg-white/5 dark:text-slate-100 dark:hover:bg-white/10",
  danger: "bg-red-700 text-white shadow-sm hover:bg-red-800 disabled:bg-red-700/50",
  ghost: "text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-white/5",
};

export function Button({
  variant = "primary",
  busy = false,
  className = "",
  children,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  return (
    <button
      type="button"
      className={`inline-flex min-h-10 items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors motion-reduce:transition-none disabled:cursor-not-allowed ${variants[variant]} ${className}`}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {busy && <span className="size-3 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden="true" />}
      {children}
    </button>
  );
}

const inputClass =
  "block w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm placeholder:text-slate-500 focus:border-brand-600 focus:outline-none focus:ring-2 focus:ring-brand-600/25 dark:border-white/15 dark:bg-slate-950 dark:text-slate-100";

export function TextField({
  label,
  hint,
  error,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string; error?: string }) {
  const id = useId();
  const hintId = `${id}-hint`;
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
      </label>
      <input id={id} className={inputClass} aria-describedby={hint || error ? hintId : undefined} aria-invalid={error ? true : undefined} {...rest} />
      {(hint || error) && (
        <p id={hintId} className={`text-xs ${error ? "text-red-700 dark:text-red-400" : "text-slate-600 dark:text-slate-400"}`}>
          {error ?? hint}
        </p>
      )}
    </div>
  );
}

export function SelectField({
  label,
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement> & { label: string; children: ReactNode }) {
  const id = useId();
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
      </label>
      <select id={id} className={inputClass} {...rest}>
        {children}
      </select>
    </div>
  );
}

export function Alert({ kind = "error", children }: { kind?: "error" | "success" | "info" | "warning"; children: ReactNode }) {
  const styles = {
    error: "border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-100",
    success: "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-100",
    info: "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-800 dark:bg-sky-950 dark:text-sky-100",
    warning: "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100",
  }[kind];
  return (
    <div role={kind === "error" ? "alert" : "status"} className={`rounded-lg border px-4 py-3 text-sm ${styles}`}>
      {children}
    </div>
  );
}

/** Card is a titled section; with a title it is a named region for assistive technology. */
export function Card({ title, actions, children, className = "" }: { title?: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  const titleId = useId();
  return (
    <section
      aria-labelledby={title ? titleId : undefined}
      className={`rounded-xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5 dark:border-white/10 dark:bg-slate-900 ${className}`}
    >
      {(title || actions) && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          {title && (
            <h2 id={titleId} className="text-[15px] font-semibold">
              {title}
            </h2>
          )}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

const badgeTones = {
  green: "bg-emerald-50 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-500/25",
  red: "bg-red-50 text-red-800 ring-red-600/20 dark:bg-red-500/10 dark:text-red-300 dark:ring-red-500/25",
  amber: "bg-amber-50 text-amber-900 ring-amber-600/25 dark:bg-amber-500/10 dark:text-amber-300 dark:ring-amber-500/25",
  blue: "bg-sky-50 text-sky-800 ring-sky-600/20 dark:bg-sky-500/10 dark:text-sky-300 dark:ring-sky-500/25",
  gray: "bg-slate-100 text-slate-700 ring-slate-500/20 dark:bg-white/5 dark:text-slate-300 dark:ring-white/15",
};

export function Badge({ tone = "gray", children }: { tone?: keyof typeof badgeTones; children: ReactNode }) {
  return <span className={`inline-flex shrink-0 items-center whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${badgeTones[tone]}`}>{children}</span>;
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

/** Dialog wraps the native <dialog> element, which provides focus trapping and Escape handling. */
export function Dialog({ open, title, onClose, children }: { open: boolean; title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onClose={onClose}
      className="m-auto w-[min(32rem,calc(100vw-2rem))] rounded-2xl border border-slate-200 bg-white p-0 text-slate-900 shadow-2xl backdrop:bg-slate-950/60 backdrop:backdrop-blur-sm dark:border-white/10 dark:bg-slate-900 dark:text-slate-100"
    >
      {open && (
        <div className="p-6">
          <h2 id={titleId} className="mb-4 text-lg font-semibold">
            {title}
          </h2>
          {children}
        </div>
      )}
    </dialog>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 py-6 text-sm text-slate-600 dark:text-slate-400">
      <span className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden="true" />
      {label}…
    </div>
  );
}

/**
 * Table renders a horizontally scrollable table so narrow screens never
 * overflow the page. The wrapper is positioned so that absolutely positioned
 * descendants (sr-only labels) are clipped by it instead of widening the page.
 */
export function Table({ caption, head, children }: { caption: string; head: ReactNode; children: ReactNode }) {
  return (
    // Focusable, so keyboard users can scroll wide tables (WCAG 2.1.1).
    <div
      className="relative -mx-4 overflow-x-auto focus-visible:outline-2 focus-visible:outline-brand-700 sm:mx-0 sm:rounded-lg sm:border sm:border-slate-200 sm:dark:border-white/10"
      tabIndex={0}
      role="region"
      aria-label={caption}
    >
      <table className="min-w-full divide-y divide-slate-200 text-left text-sm dark:divide-slate-800">
        <caption className="sr-only">{caption}</caption>
        <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-600 dark:bg-white/5 dark:text-slate-400">{head}</thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{children}</tbody>
      </table>
    </div>
  );
}

export const th = "whitespace-nowrap px-4 py-2.5 font-medium";
export const td = "whitespace-nowrap px-4 py-2.5";

const avatarTones = [
  "bg-teal-700",
  "bg-sky-700",
  "bg-indigo-600",
  "bg-violet-600",
  "bg-fuchsia-700",
  "bg-rose-700",
  "bg-orange-700",
  "bg-emerald-700",
];

/** hashName picks a stable colour for a name. */
export function hashName(name: string): number {
  let h = 0;
  for (const c of name) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return h;
}

/** initials takes up to two letters from a name ("home-assistant" → "HA"). */
export function initials(name: string): string {
  const words = name.split(/[\s._-]+/).filter(Boolean);
  const letters = words.length > 1 ? words[0]![0]! + words[1]![0]! : name.slice(0, 2);
  return letters.toUpperCase();
}

/** Avatar is a coloured tile with initials; it stands in for app and user pictures. */
export function Avatar({ name, className = "size-10 text-sm", rounded = "rounded-full" }: { name: string; className?: string; rounded?: string }) {
  return (
    <span aria-hidden="true" className={`inline-flex shrink-0 select-none items-center justify-center font-semibold text-white ${rounded} ${avatarTones[hashName(name) % avatarTones.length]} ${className}`}>
      {initials(name)}
    </span>
  );
}

/** Meter is a usage bar; the number next to it carries the meaning. */
export function Meter({ percent, className = "" }: { percent: number; className?: string }) {
  const pct = Math.max(0, Math.min(100, percent));
  const tone = pct >= 90 ? "bg-red-600" : pct >= 75 ? "bg-amber-500" : "bg-brand-600";
  return (
    <div className={`h-1.5 overflow-hidden rounded-full bg-slate-200 dark:bg-white/10 ${className}`} aria-hidden="true">
      <div className={`h-full rounded-full ${tone}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

/** EmptyState explains an empty list and offers the next step. */
export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center rounded-xl border border-dashed border-slate-300 px-6 py-10 text-center dark:border-white/15">
      <p className="font-medium">{title}</p>
      {children && <p className="mt-1 max-w-md text-sm text-slate-600 dark:text-slate-400">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/** BackLink leads from a detail page to its list. */
export function BackLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <p className="mb-3 text-sm">
      <Link to={to} className="inline-flex items-center gap-1 font-medium text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white">
        <Icon name="chevronLeft" className="size-4" />
        {children}
      </Link>
    </p>
  );
}

/**
 * IconButton is a compact action for rows and toolbars. The label is its
 * accessible name and tooltip, so lists stay readable without hiding what
 * each button does from assistive technology.
 */
export function IconButton({
  icon,
  label,
  tone = "default",
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { icon: IconName; label: string; tone?: "default" | "danger" }) {
  return (
    <button type="button" aria-label={label} title={label} className={`${iconButtonClass(tone)} ${className}`} {...rest}>
      <Icon name={icon} className="size-[18px]" />
    </button>
  );
}

export function iconButtonClass(tone: "default" | "danger" = "default"): string {
  return `inline-flex size-9 shrink-0 items-center justify-center rounded-lg disabled:opacity-50 ${
    tone === "danger"
      ? "text-red-700 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-500/10"
      : "text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-white/10 dark:hover:text-white"
  }`;
}

const appGradients = [
  "from-teal-500 to-emerald-700",
  "from-sky-500 to-blue-700",
  "from-indigo-500 to-violet-700",
  "from-violet-500 to-fuchsia-700",
  "from-rose-500 to-red-700",
  "from-orange-500 to-rose-700",
  "from-amber-500 to-orange-700",
  "from-cyan-500 to-sky-700",
];

/**
 * AppIcon is the picture of an app: a gradient tile with its initials, until
 * catalogs carry icons. The colour is stable per name.
 */
export function AppIcon({ name, size = "md" }: { name: string; size?: "sm" | "md" | "lg" }) {
  const dims = { sm: "size-10 rounded-xl text-sm", md: "size-12 rounded-[14px] text-base", lg: "size-16 rounded-[20px] text-xl sm:size-[72px] sm:rounded-[22px]" }[size];
  return (
    <span
      aria-hidden="true"
      className={`inline-flex shrink-0 select-none items-center justify-center bg-gradient-to-br font-semibold tracking-tight text-white shadow-md shadow-slate-900/15 ring-1 ring-inset ring-white/20 ${dims} ${appGradients[hashName(name) % appGradients.length]}`}
    >
      {initials(name)}
    </span>
  );
}

/** Glass is the frosted surface of the home desktop. */
export const glass =
  "rounded-2xl border border-white/60 bg-white/70 shadow-lg shadow-slate-900/5 backdrop-blur-xl dark:border-white/10 dark:bg-slate-900/60 dark:shadow-black/20";
