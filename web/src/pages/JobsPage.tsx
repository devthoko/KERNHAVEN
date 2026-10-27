import { useState } from "react";
import { JobProgress, JobStateBadge } from "../components/JobBits";
import { Alert, Card, PageHeader, SelectField, Spinner, Table, td, th } from "../components/ui";
import { api } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { Link } from "../lib/router";
import { ACTIVE_JOB_STATES, type Job } from "../lib/types";
import { useData } from "../lib/useData";

const STATES = ["", "queued", "running", "compensating", "succeeded", "failed", "cancelled"] as const;

export function JobsPage() {
  const [state, setState] = useState<(typeof STATES)[number]>("");
  const { data, error, loading } = useData(
    () => api.get<{ jobs: Job[] }>(`/jobs?limit=100${state ? `&state=${state}` : ""}`),
    [state],
    { refreshMs: 2000, shouldPoll: (d) => d.jobs.some((j) => ACTIVE_JOB_STATES.includes(j.state)) },
  );

  return (
    <>
      <PageHeader title="Jobs" description="Background operations with their progress. Active jobs refresh automatically." />
      <Card>
        <div className="mb-4 max-w-xs">
          <SelectField label="State" value={state} onChange={(e) => setState(e.target.value as (typeof STATES)[number])}>
            {STATES.map((s) => (
              <option key={s} value={s}>
                {s === "" ? "All states" : s}
              </option>
            ))}
          </SelectField>
        </div>
        {loading && !data && <Spinner />}
        {error && <Alert>{error}</Alert>}
        {data && data.jobs.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">No jobs match this filter.</p>}
        {data && data.jobs.length > 0 && (
          <Table
            caption="Jobs"
            head={
              <tr>
                <th className={th}>Job</th>
                <th className={th}>State</th>
                <th className={th}>Progress</th>
                <th className={th}>Attempts</th>
                <th className={th}>Created</th>
              </tr>
            }
          >
            {data.jobs.map((j) => (
              <tr key={j.id}>
                <td className={td}>
                  <Link to={`/jobs/${j.id}`} className="font-medium text-brand-700 underline dark:text-brand-500">
                    #{j.id} {j.kind}
                  </Link>
                </td>
                <td className={td}>
                  <JobStateBadge state={j.state} />
                </td>
                <td className={td}>
                  <JobProgress job={j} />
                </td>
                <td className={td}>
                  {j.attempts}/{j.max_attempts}
                </td>
                <td className={td}>{formatDateTime(j.created_at)}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}
