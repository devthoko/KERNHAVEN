import type { Theme } from "./types";

const media = typeof window !== "undefined" ? window.matchMedia("(prefers-color-scheme: dark)") : null;
let listener: (() => void) | null = null;

/** applyTheme sets the "dark" class on <html>, following the OS for "system". */
export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  const update = () => {
    const dark = theme === "dark" || (theme === "system" && !!media?.matches);
    root.classList.toggle("dark", dark);
    root.dataset.theme = theme;
  };
  if (listener && media) media.removeEventListener("change", listener);
  listener = theme === "system" ? update : null;
  if (listener && media) media.addEventListener("change", listener);
  update();
}
