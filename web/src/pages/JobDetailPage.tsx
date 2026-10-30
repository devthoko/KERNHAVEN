import { useState } from "react";
import { JobProgress, JobStateBadge } from "../components/JobBits";
import { Alert, BackLink, Badge, Button, Card, Dialog, PageHeader, Spinner } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { useSession } from "../lib/session";
import { ACTIVE_JOB_STATES, type Job } from "../lib/types";
import { useData } from "../lib/useData";

const stepTone = { pending: "gray", done: "green", compensated: "amber" } as const;
const logTone = { info: "text-slate-700 dark:text-slate-300", warn: "text-amber-800 dark:text-amber-300", error: "text-red-800 dark:text-red-300" };

export function JobDetailPage({ id }: { id: string }) {
  const { can } = useSession();
  const { data: job, error, loading, reload } = useData(() => api.get<Job>(`/jobs/${encodeURIComponent(id)}`), [id], {
    refreshMs: 1500,
    shouldPoll: (j) => ACTIVE_JOB_STATES.includes(j.state),
  });
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const cancel = async () => {
    setBusy(true);
    setActionError(null);
    try {
      await api.post(`/jobs/${encodeURIComponent(id)}/cancel`);
      setConfirm(false);
      await reload();
    } catch (err) {
      setActionError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (loading && !job) return <Spinner />;
  if (!job) return <Alert>{error ?? "Job not found."}</Alert>;
  const active = ACTIVE_JOB_STATES.includes(job.state);

  return (
    <>
      <BackLink to="/jobs">All jobs</BackLink>
      <PageHeader
        title={`Job #${job.id}`}
        description={job.kind}
        actions={
          can("jobs.manage") && active && !job.cancel_requested ? (
            <Button variant="danger" onClick={() => setConfirm(true)}>
              Cancel job
            </Button>
          ) : undefined
        }
      />
      {error && <Alert>{error}</Alert>}
      {actionError && <Alert>{actionError}</Alert>}
      {job.needs_attention && <Alert kind="warning">Rollback failed. Manual attention is required: {job.error}</Alert>}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Status" className="lg:col-span-1">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-slate-600 dark:text-slate-400">State</dt>
            <dd>
              <JobStateBadge state={job.state} /> {job.cancel_requested && active && <Badge tone="amber">Cancel requested</Badge>}
            </dd>
            <dt className="text-slate-600 dark:text-slate-400">Progress</dt>
            <dd>
              <JobProgress job={job} />
            </dd>
            <dt className="text-slate-600 dark:text-slate-400">Attempts</dt>
            <dd>
              {job.attempts} of {job.max_attempts}
            </dd>
            <dt className="text-slate-600 dark:text-slate-400">Created</dt>
            <dd>{formatDateTime(job.created_at)}</dd>
            <dt className="text-slate-600 dark:text-slate-400">Started</dt>
            <dd>{formatDateTime(job.started_at)}</dd>
            <dt className="text-slate-600 dark:text-slate-400">Finished</dt>
            <dd>{formatDateTime(job.finished_at)}</dd>
          </dl>
          {job.error && !job.needs_attention && <p className="mt-3 break-words text-sm text-red-800 dark:text-red-300">{job.error}</p>}
        </Card>
        <Card title="Steps" className="lg:col-span-2">
          <ol className="space-y-2">
            {job.steps?.map((s) => (
              <li key={s.index} className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span>
                  {s.index + 1}. {s.name}
                </span>
                <span className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
                  {s.completed_at && formatDateTime(s.completed_at)}
                  <Badge tone={stepTone[s.state]}>{s.state}</Badge>
                </span>
              </li>
            ))}
          </ol>
        </Card>
        <Card title="Log" className="lg:col-span-3">
          {!job.logs?.length ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">No log entries.</p>
          ) : (
            <ol className="max-h-96 space-y-1 overflow-y-auto font-mono text-xs">
              {job.logs.map((l, i) => (
                <li key={i} className={`break-words ${logTone[l.level]}`}>
                  <time dateTime={l.time} className="text-slate-500 dark:text-slate-400">
                    {formatDateTime(l.time)}
                  </time>{" "}
                  [{l.level}] {l.message}
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>
      <Dialog open={confirm} title="Cancel this job?" onClose={() => setConfirm(false)}>
        <p className="text-sm">The current step is interrupted and completed steps are rolled back where the job supports it.</p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setConfirm(false)}>
            Keep running
          </Button>
          <Button variant="danger" busy={busy} onClick={cancel}>
            Cancel job
          </Button>
        </div>
      </Dialog>
    </>
  );
}
