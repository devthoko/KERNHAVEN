import type { Job, JobState } from "../lib/types";
import { capitalize, DotBadge } from "./ui";

const tones: Record<JobState, "green" | "red" | "amber" | "blue" | "gray"> = {
  queued: "gray",
  running: "blue",
  compensating: "amber",
  succeeded: "green",
  failed: "red",
  cancelled: "gray",
};

const labels: Record<JobState, string> = {
  queued: "Queued",
  running: "Running",
  compensating: "Rolling back",
  succeeded: "Succeeded",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function JobStateBadge({ state }: { state: JobState | string }) {
  return <DotBadge tone={tones[state as JobState] ?? "gray"}>{labels[state as JobState] ?? capitalize(state)}</DotBadge>;
}

export function JobProgress({ job }: { job: Job }) {
  const pct = job.steps_total ? Math.round((job.steps_done / job.steps_total) * 100) : 0;
  return (
    <div className="flex items-center gap-2">
      <div
        className="h-2 w-24 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700"
        role="progressbar"
        aria-label={`Job ${job.id} progress`}
        aria-valuemin={0}
        aria-valuemax={job.steps_total}
        aria-valuenow={job.steps_done}
      >
        <div className="h-full bg-brand-600" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-600 dark:text-slate-400">
        {job.steps_done}/{job.steps_total}
      </span>
    </div>
  );
}

const jobTitles: Record<string, string> = {
  "stacks.deploy": "Deploy stack",
  "stacks.down": "Stop stack",
  "images.pull": "Pull image",
  "storage.format": "Format disk",
  "files.copy": "Copy files",
  "files.purge": "Empty trash",
  "tls.issue": "Issue certificate",
  "backup.run": "Back up",
  "backup.verify": "Verify backup",
  "backup.restore_stack": "Restore app data",
  "backup.restore_platform": "Restore platform",
};

/** jobTitle names a job kind in words ("backup.run" → "Back up"); unknown kinds are spelled out. */
export function jobTitle(kind: string): string {
  const known = jobTitles[kind];
  if (known) return known;
  const last = kind.split(".").pop() ?? kind;
  const words = last.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** isHousekeeping marks the platform's own scheduled jobs, which are not news for people. */
export function isHousekeeping(kind: string): boolean {
  return kind.startsWith("maintenance.");
}
