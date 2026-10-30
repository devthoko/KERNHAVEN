import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { useRouter } from "../lib/router";

/**
 * Popover is a button with a small non-modal panel (account menu,
 * notifications). It closes on Escape (focus returns to the button), on a
 * click outside and when the page changes.
 */
export function Popover({
  label,
  trigger,
  children,
  className = "",
  width = "sm:w-80",
}: {
  label: string;
  trigger: ReactNode;
  children: (close: () => void) => ReactNode;
  className?: string;
  width?: string;
}) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const id = useId();
  const { path } = useRouter();

  useEffect(() => setOpen(false), [path]);
  useEffect(() => {
    if (!open) return;
    const outside = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        button.current?.focus();
      }
    };
    document.addEventListener("mousedown", outside);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", outside);
      document.removeEventListener("keydown", key);
    };
  }, [open]);

  return (
    <div ref={box} className="relative">
      <button
        ref={button}
        type="button"
        aria-label={label}
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
        className={`inline-flex items-center justify-center rounded-full ${className}`}
      >
        {trigger}
      </button>
      {open && (
        <div
          id={id}
          role="dialog"
          aria-label={label}
          className={`z-50 max-sm:fixed max-sm:inset-x-4 max-sm:top-16 sm:absolute sm:right-0 sm:top-full sm:mt-2 ${width} sm:max-w-[calc(100vw-2rem)] origin-top-right rounded-2xl border border-slate-200 bg-white p-2 text-slate-900 shadow-2xl shadow-slate-900/10 dark:border-white/10 dark:bg-slate-900 dark:text-slate-100`}
        >
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  );
}
