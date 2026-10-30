/**
 * Icon draws a small stroke icon from Kernhaven's own set (24×24 grid,
 * currentColor). Icons are decorative: the element next to them carries the
 * accessible name, so they are hidden from assistive technology.
 */
const paths = {
  home: "M3 10.5 12 3l9 7.5M5 9v11h5v-6h4v6h5V9",
  apps: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
  store: "M4 8h16l-1.2 11.1A2 2 0 0 1 16.8 21H7.2a2 2 0 0 1-2-1.9zM8.5 8V6.5a3.5 3.5 0 0 1 7 0V8",
  folder: "M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2.5h8.5A1.5 1.5 0 0 1 21 9v9.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z",
  disk: "M3 14h18M3 14l2.5-8.5A2 2 0 0 1 7.4 4h9.2a2 2 0 0 1 1.9 1.5L21 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5zM7 17h.01M11 17h.01",
  backup: "M4 12a8 8 0 1 0 2.3-5.7M4 4v4h4M12 8v4l3 2",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  bell: "M6 16V11a6 6 0 1 1 12 0v5l1.5 2h-15zM10 21h4",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3",
  box: "M12 3 20 7.5v9L12 21l-8-4.5v-9zM4 7.5l8 4.5 8-4.5M12 12v9",
  jobs: "M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01",
  users: "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M2 21v-1a6 6 0 0 1 6-6h2a6 6 0 0 1 6 6v1M16 3.3a4 4 0 0 1 0 7.4M22 21v-1a6 6 0 0 0-4-5.6",
  shield: "M12 3 4.5 6v5.5c0 4.6 3.2 8.3 7.5 9.5 4.3-1.2 7.5-4.9 7.5-9.5V6zM9 12l2 2 4-4",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-2.9-1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.7 1.7 0 0 0 3 15H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.2-2.9l-.1-.1A2 2 0 1 1 7 5.2l.1.1A1.7 1.7 0 0 0 10 4.1V4a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1A1.7 1.7 0 0 0 21 11h.1a2 2 0 1 1 0 4z",
  logout: "M15 4h3.5A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5H15M10 16l-4-4 4-4M6 12h10",
  menu: "M4 6h16M4 12h16M4 18h16",
  close: "M6 6l12 12M18 6 6 18",
  plus: "M12 5v14M5 12h14",
  external: "M14 4h6v6M20 4l-9 9M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10",
  chevronRight: "M9 6l6 6-6 6",
  chevronLeft: "M15 6l-6 6 6 6",
  cpu: "M7 7h10v10H7zM10 10h4v4h-4zM9 3v4M15 3v4M9 17v4M15 17v4M3 9h4M3 15h4M17 9h4M17 15h4",
  memory: "M3 7h18v9H3zM7 16v3M12 16v3M17 16v3M7 10v3M11 10v3M15 10v3",
  network: "M12 20V10M8 14l4-4 4 4M5 5h14",
  check: "M5 12.5 10 17l9-10",
  warning: "M12 4 2.5 20h19zM12 10v4M12 17h.01",
  info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M12 11v5M12 8h.01",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14M20 20l-4-4",
  sun: "M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4",
  moon: "M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5",
  more: "M5 12h.01M12 12h.01M19 12h.01",
  eye: "M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6",
  download: "M12 4v11M7.5 10.5 12 15l4.5-4.5M4 19h16",
  upload: "M12 15V4M7.5 8.5 12 4l4.5 4.5M4 19h16",
  pencil: "M15.5 4.5l4 4L8 20H4v-4zM13 7l4 4",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
  file: "M14 3H6.5A1.5 1.5 0 0 0 5 4.5v15A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V8zM14 3v5h5",
  folderPlus: "M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2.5h8.5A1.5 1.5 0 0 1 21 9v9.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5zM12 11v6M9 14h6",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
} as const;

export type IconName = keyof typeof paths;

export function Icon({ name, className = "size-5" }: { name: IconName; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 ${className}`} aria-hidden="true" focusable="false">
      <path d={paths[name]} />
    </svg>
  );
}
