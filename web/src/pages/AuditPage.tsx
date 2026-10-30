import { useState, type FormEvent } from "react";
import { Alert, Button, Card, DotBadge, PageHeader, SelectField, Spinner, Table, TextField, buttonClass, capitalize, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type { AuditEvent, VerifyResult } from "../lib/types";

const PAGE = 50;

type Filters = { q: string; action: string; actor: string; result: string; since: string; until: string };
const empty: Filters = { q: "", action: "", actor: "", result: "", since: "", until: "" };

/** query turns the form into API parameters; dates are local days. */
function query(f: Filters): URLSearchParams {
  const q = new URLSearchParams();
  for (const k of ["q", "action", "actor", "result"] as const) if (f[k].trim()) q.set(k, f[k].trim());
  if (f.since) q.set("since", new Date(`${f.since}T00:00:00`).toISOString().replace(/\.\d{3}Z$/, "Z"));
  if (f.until) {
    const d = new Date(`${f.until}T00:00:00`);
    d.setDate(d.getDate() + 1); // the whole "until" day
    q.set("until", d.toISOString().replace(/\.\d{3}Z$/, "Z"));
  }
  return q;
}

export function AuditPage() {
  const [filters, setFilters] = useState<Filters>(empty);
  const [applied, setApplied] = useState(filters);
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [more, setMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  const load = async (f: typeof filters, before?: number) => {
    setBusy(true);
    setError(null);
    const q = query(f);
    q.set("limit", String(PAGE));
    if (before) q.set("before", String(before));
    try {
      const res = await api.get<{ events: AuditEvent[] }>(`/audit?${q}`);
      setEvents((prev) => (before && prev ? [...prev, ...res.events] : res.events));
      setMore(res.events.length === PAGE);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (events === null && !busy && !error) void load(applied);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setApplied(filters);
    void load(filters);
  };

  const runVerify = async () => {
    setVerifying(true);
    try {
      setVerify(await api.get<VerifyResult>("/audit/verify"));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Tamper-evident record of security-relevant actions."
        actions={
          <span className="flex gap-2">
            <a
              className={buttonClass("secondary")}
              href={`/api/v1/audit/export?${query(applied)}`}
              download
            >
              Export (JSON Lines)
            </a>
            <Button variant="secondary" busy={verifying} onClick={runVerify}>
              Verify integrity
            </Button>
          </span>
        }
      />
      {verify && (
        <div className="mb-4">
          {verify.ok ? (
            <Alert kind="success">Integrity verified: {verify.records} records, hash chain intact.</Alert>
          ) : (
            <Alert>
              Integrity check failed at record {verify.broken_at}: {verify.reason}. The audit log has been modified outside Kernhaven.
            </Alert>
          )}
        </div>
      )}
      <Card>
        <form onSubmit={submit} className="mb-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-[2fr_1fr_1fr_1fr_1fr_1fr_auto] lg:items-end">
          <TextField label="Search" type="search" placeholder="host, IP, request ID…" maxLength={200} value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
          <TextField label="Action" placeholder="e.g. auth.login" value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })} />
          <TextField label="Actor" placeholder="username" value={filters.actor} onChange={(e) => setFilters({ ...filters, actor: e.target.value })} />
          <SelectField label="Result" value={filters.result} onChange={(e) => setFilters({ ...filters, result: e.target.value })}>
            <option value="">Any</option>
            <option value="success">success</option>
            <option value="failure">failure</option>
            <option value="denied">denied</option>
          </SelectField>
          <TextField label="From" type="date" value={filters.since} onChange={(e) => setFilters({ ...filters, since: e.target.value })} />
          <TextField label="To" type="date" value={filters.until} onChange={(e) => setFilters({ ...filters, until: e.target.value })} />
          <Button type="submit" variant="secondary">
            Filter
          </Button>
        </form>
        <p className="mb-4 text-xs text-slate-600 dark:text-slate-400">
          The export contains the chain hashes. Keep exports outside this server; <code>kernhaven-core audit-check new.jsonl old.jsonl</code> shows whether the log was truncated or rewritten in between.
        </p>
        {error && <Alert>{error}</Alert>}
        {events === null && busy && <Spinner />}
        {events && events.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">No events match.</p>}
        {events && events.length > 0 && (
          <Table
            caption="Audit events"
            head={
              <tr>
                <th className={th}>#</th>
                <th className={th}>Time</th>
                <th className={th}>Actor</th>
                <th className={th}>Action</th>
                <th className={th}>Target</th>
                <th className={th}>Result</th>
                <th className={th}>Address</th>
                <th className={th}>Details</th>
              </tr>
            }
          >
            {events.map((e) => (
              <tr key={e.seq}>
                <td className={td}>{e.seq}</td>
                <td className={td}>{formatDateTime(e.time)}</td>
                <td className={td}>{e.actor}</td>
                <td className={`${td} font-mono text-xs`}>{e.action}</td>
                <td className={td}>{e.target}</td>
                <td className={td}>
                  <DotBadge tone={e.result === "success" ? "green" : e.result === "denied" ? "amber" : "red"}>{capitalize(e.result)}</DotBadge>
                </td>
                <td className={td}>{e.ip}</td>
                <td className={`${td} font-mono text-xs`}>
                  {Object.entries(e.details)
                    .map(([k, v]) => `${k}=${v}`)
                    .join(" ")}
                </td>
              </tr>
            ))}
          </Table>
        )}
        {more && events && (
          <div className="mt-4">
            <Button variant="secondary" busy={busy} onClick={() => load(applied, events[events.length - 1]?.seq)}>
              Load older events
            </Button>
          </div>
        )}
      </Card>
    </>
  );
}
