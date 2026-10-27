import { useState, type FormEvent } from "react";
import { Alert, Badge, Button, Card, PageHeader, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type { AuditEvent, VerifyResult } from "../lib/types";

const PAGE = 50;

export function AuditPage() {
  const [filters, setFilters] = useState({ action: "", actor: "" });
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
    const q = new URLSearchParams({ limit: String(PAGE) });
    if (f.action) q.set("action", f.action);
    if (f.actor) q.set("actor", f.actor);
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
    const f = { action: filters.action.trim(), actor: filters.actor.trim() };
    setApplied(f);
    void load(f);
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
          <Button variant="secondary" busy={verifying} onClick={runVerify}>
            Verify integrity
          </Button>
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
        <form onSubmit={submit} className="mb-4 grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
          <TextField label="Action" placeholder="e.g. auth.login" value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })} />
          <TextField label="Actor" placeholder="username" value={filters.actor} onChange={(e) => setFilters({ ...filters, actor: e.target.value })} />
          <Button type="submit" variant="secondary">
            Filter
          </Button>
        </form>
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
                  <Badge tone={e.result === "success" ? "green" : e.result === "denied" ? "amber" : "red"}>{e.result}</Badge>
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
