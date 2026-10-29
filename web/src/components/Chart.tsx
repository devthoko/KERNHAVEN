import { formatBytes } from "../lib/format";
import type { MetricHistory, MetricPoint } from "../lib/types";

export function formatValue(v: number, unit: MetricHistory["unit"]): string {
  switch (unit) {
    case "percent":
      return `${v.toFixed(v < 10 ? 1 : 0)} %`;
    case "bytes":
      return formatBytes(v);
    case "bytes/s":
      return `${formatBytes(v)}/s`;
    case "celsius":
      return `${v.toFixed(1)} °C`;
    default:
      return v.toFixed(2);
  }
}

export interface Line {
  label: string;
  points: MetricPoint[];
  className: string; // stroke colour classes
}

const W = 600;
const H = 160;
const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const dayFmt = new Intl.DateTimeFormat(undefined, { weekday: "short", hour: "2-digit", minute: "2-digit" });

/**
 * Chart draws one or more series as lines (averages) with the maxima as a
 * thin dashed line. Axis labels are HTML so they keep their size; the SVG
 * only holds the lines, and its label summarizes them for screen readers.
 */
export function Chart({ title, unit, lines, long = false }: { title: string; unit: MetricHistory["unit"]; lines: Line[]; long?: boolean }) {
  const all = lines.flatMap((l) => l.points);
  if (all.length < 2) {
    return (
      <figure className="space-y-1">
        <figcaption className="text-sm font-medium">{title}</figcaption>
        <p className="text-sm text-slate-600 dark:text-slate-400">Not enough data yet.</p>
      </figure>
    );
  }
  const t0 = Math.min(...all.map((p) => new Date(p.t).getTime()));
  const t1 = Math.max(...all.map((p) => new Date(p.t).getTime()));
  let top = Math.max(...all.map((p) => p.max));
  if (unit === "percent") top = Math.max(top, 10);
  if (top <= 0) top = 1;
  const x = (t: string) => ((new Date(t).getTime() - t0) / Math.max(1, t1 - t0)) * W;
  const y = (v: number) => H - 2 - (v / top) * (H - 4);
  const path = (pts: MetricPoint[], key: "avg" | "max") => pts.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p[key]).toFixed(1)}`).join(" ");
  const fmt = long ? dayFmt : timeFmt;
  const summary = lines
    .map((l) => {
      const last = l.points[l.points.length - 1];
      const peak = Math.max(...l.points.map((p) => p.max));
      return `${l.label}: now ${last ? formatValue(last.avg, unit) : "—"}, peak ${formatValue(peak, unit)}`;
    })
    .join("; ");
  const axis = "text-xs text-slate-600 dark:text-slate-400";
  return (
    <figure className="space-y-1">
      <figcaption className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
        <span className="font-medium">{title}</span>
        <span className={`flex flex-wrap gap-3 ${axis}`}>
          {lines.map((l) => (
            <span key={l.label} className="inline-flex items-center gap-1">
              <svg width="12" height="4" aria-hidden="true">
                <line x1="0" y1="2" x2="12" y2="2" strokeWidth="3" className={l.className} />
              </svg>
              {l.label} {l.points.length > 0 && formatValue(l.points[l.points.length - 1]!.avg, unit)}
            </span>
          ))}
        </span>
      </figcaption>
      <div className="grid grid-cols-[auto_1fr] gap-x-2">
        <div className={`flex h-32 flex-col justify-between text-right ${axis}`} aria-hidden="true">
          <span>{formatValue(top, unit)}</span>
          <span>0</span>
        </div>
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-32 w-full border-b border-l border-slate-300 dark:border-slate-700" role="img" aria-label={`${title}. ${summary}`}>
          {lines.map((l) => (
            <g key={l.label} fill="none" className={l.className}>
              <path d={path(l.points, "max")} strokeWidth="1" strokeDasharray="3 3" opacity="0.6" vectorEffect="non-scaling-stroke" />
              <path d={path(l.points, "avg")} strokeWidth="2" vectorEffect="non-scaling-stroke" />
            </g>
          ))}
        </svg>
        <span />
        <div className={`flex justify-between ${axis}`} aria-hidden="true">
          <span>{fmt.format(t0)}</span>
          <span>{fmt.format(t1)}</span>
        </div>
      </div>
    </figure>
  );
}
