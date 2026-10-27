import { useEffect, useState } from "react";
import { StateBadge } from "../components/DockerBits";
import { StackEditor, toInput, toRows, type VariableRow } from "../components/StackEditor";
import { Alert, Badge, Button, Card, Dialog, PageHeader, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import type { StackDetail, StackEvaluation, StackException, StackRevision } from "../lib/types";
import { useData } from "../lib/useData";
import { statusTone } from "./StacksPage";

export function StackDetailPage({ name }: { name: string }) {
  const { can } = useSession();
  const { navigate } = useRouter();
  const { data, error, loading, reload } = useData(() => api.get<StackDetail>(`/stacks/${encodeURIComponent(name)}`), [name], { refreshMs: 3000 });
  const revisions = useData(() => api.get<{ revisions: StackRevision[] }>(`/stacks/${encodeURIComponent(name)}/revisions`), [name, data?.stack.latest_revision]);
  const [editing, setEditing] = useState(false);
  const [compose, setCompose] = useState("");
  const [variables, setVariables] = useState<VariableRow[]>([]);
  const [exceptions, setExceptions] = useState<StackException[]>([]);
  const [comment, setComment] = useState("");
  const [evaluation, setEvaluation] = useState<StackEvaluation | null>(null);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string; job?: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmDown, setConfirmDown] = useState(false);
  const [removeVolumes, setRemoveVolumes] = useState(false);

  // Start editing from the latest revision.
  const edit = async (from?: number) => {
    const rev = from ? await api.get<StackRevision>(`/stacks/${encodeURIComponent(name)}/revisions/${from}`) : data?.latest;
    if (!rev || !data) return;
    setCompose(rev.compose ?? "");
    setExceptions(rev.exceptions);
    setVariables(toRows(data.variables));
    setComment(from ? `restore revision ${from}` : "");
    setEditing(true);
  };
  useEffect(() => setEditing(false), [name]);

  const run = async (f: () => Promise<{ job_id?: number } | void>, success: string) => {
    setBusy(true);
    setNotice(null);
    try {
      const res = await f();
      setNotice({ kind: "success", text: success, job: res && "job_id" in res ? res.job_id : undefined });
      await reload();
    } catch (err) {
      setNotice({ kind: "error", text: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  if (loading && !data) return <Spinner />;
  if (!data) return <Alert>{error ?? "Stack not found."}</Alert>;
  const st = data.stack;
  // Stacks of installed apps change only through the app pages (M8).
  const managed = st.managed_by === "app";
  const manage = can("containers.manage") && !managed;

  return (
    <>
      <p className="mb-2 text-sm">
        <Link to="/stacks" className="text-brand-700 underline dark:text-brand-500">
          ← All stacks
        </Link>
      </p>
      <PageHeader
        title={st.name}
        description={`Latest revision ${st.latest_revision}${st.deployed_revision ? ` · deployed revision ${st.deployed_revision}` : " · not deployed"}`}
        actions={
          manage && !editing ? (
            <>
              <Button busy={busy} disabled={st.status === "deploying" || st.status === "stopping"} onClick={() => run(() => api.post(`/stacks/${name}/deploy`), `Deploying revision ${st.latest_revision}.`)}>
                Deploy latest
              </Button>
              <Button variant="secondary" onClick={() => edit()}>
                Edit
              </Button>
              {st.deployed_revision > 0 && (
                <Button variant="danger" onClick={() => setConfirmDown(true)}>
                  Take down
                </Button>
              )}
              {st.deployed_revision === 0 && st.status !== "deploying" && (
                <Button variant="ghost" className="text-red-700 dark:text-red-400" onClick={() => run(async () => { await api.del(`/stacks/${name}`); navigate("/stacks"); }, "Deleted.")}>
                  Delete
                </Button>
              )}
            </>
          ) : undefined
        }
      />
      {notice && (
        <div className="mb-4">
          <Alert kind={notice.kind}>
            {notice.text}{" "}
            {notice.job && (
              <Link to={`/jobs/${notice.job}`} className="underline">
                Follow job #{notice.job}
              </Link>
            )}
          </Alert>
        </div>
      )}
      {managed && (
        <div className="mb-4">
          <Alert kind="info">
            This stack belongs to an installed app.{" "}
            <Link to={`/apps/${st.name}`} className="underline">
              Manage it on the app page
            </Link>
            .
          </Alert>
        </div>
      )}
      {st.status === "failed" && st.status_message && (
        <div className="mb-4">
          <Alert>{st.status_message}</Alert>
        </div>
      )}

      {editing ? (
        <>
          <StackEditor stackName={name} compose={compose} onCompose={setCompose} variables={variables} onVariables={setVariables} exceptions={exceptions} onExceptions={setExceptions} onEvaluation={setEvaluation} />
          <Card className="mt-4">
            <div className="grid gap-3 sm:grid-cols-[1fr_auto_auto_auto] sm:items-end">
              <TextField label="Change note" value={comment} onChange={(e) => setComment(e.target.value)} />
              <Button
                busy={busy}
                disabled={!evaluation?.deployable}
                onClick={() =>
                  run(async () => {
                    await api.post(`/stacks/${name}/revisions`, { compose, comment, variables: toInput(variables), exceptions });
                    setEditing(false);
                    return api.post<{ job_id: number }>(`/stacks/${name}/deploy`);
                  }, "Saved a new revision and started the deployment.")
                }
              >
                Save and deploy
              </Button>
              <Button variant="secondary" busy={busy} disabled={!evaluation?.deployable} onClick={() => run(async () => { await api.post(`/stacks/${name}/revisions`, { compose, comment, variables: toInput(variables), exceptions }); setEditing(false); }, "Saved a new revision.")}>
                Save
              </Button>
              <Button variant="ghost" onClick={() => setEditing(false)}>
                Cancel
              </Button>
            </div>
          </Card>
        </>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card title="Status">
            <p className="mb-3">
              <Badge tone={statusTone[st.status]}>{st.status}</Badge>
            </p>
            {data.services_error && <Alert kind="warning">{data.services_error}</Alert>}
            {data.services && data.services.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">No containers are running.</p>}
            {data.services && data.services.length > 0 && (
              <Table caption="Services" head={<tr><th className={th}>Service</th><th className={th}>State</th><th className={th}>Revision</th></tr>}>
                {data.services.map((s) => (
                  <tr key={s.container}>
                    <td className={td}>
                      <Link to={`/containers/${s.container}`} className="text-brand-700 underline dark:text-brand-500">
                        {s.service}
                      </Link>
                    </td>
                    <td className={td}>
                      <StateBadge state={s.state} />
                    </td>
                    <td className={td}>{s.revision}</td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
          <Card title="Variables">
            {data.variables.length === 0 ? (
              <p className="text-sm text-slate-600 dark:text-slate-400">No variables.</p>
            ) : (
              <ul className="space-y-1 text-sm">
                {data.variables.map((v) => (
                  <li key={v.name} className="flex flex-wrap gap-2">
                    <code>{v.name}</code>
                    {v.secret ? <Badge tone="amber">secret · set</Badge> : <span className="break-all">{v.value}</span>}
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Revisions" className="lg:col-span-2">
            {revisions.data && (
              <Table caption="Revisions" head={<tr><th className={th}>#</th><th className={th}>Note</th><th className={th}>By</th><th className={th}>Created</th><th className={th}>Exceptions</th>{manage && <th className={th}><span className="sr-only">Actions</span></th>}</tr>}>
                {revisions.data.revisions.map((r) => (
                  <tr key={r.number}>
                    <td className={td}>
                      {r.number} {r.number === st.deployed_revision && <Badge tone="green">deployed</Badge>}
                    </td>
                    <td className={`${td} max-w-64 truncate`} title={r.comment}>{r.comment || "—"}</td>
                    <td className={td}>{r.created_by}</td>
                    <td className={td}>{formatDateTime(r.created_at)}</td>
                    <td className={td}>{r.exceptions.length ? r.exceptions.map((x) => `${x.service}: ${x.rule}`).join(", ") : "none"}</td>
                    {manage && (
                      <td className={`${td} text-right`}>
                        <div className="flex justify-end gap-1">
                          {r.number !== st.deployed_revision && (
                            <Button variant="ghost" aria-label={`Deploy revision ${r.number}`} onClick={() => run(() => api.post(`/stacks/${name}/deploy`, { revision: r.number }), `Deploying revision ${r.number}.`)}>
                              Deploy
                            </Button>
                          )}
                          <Button variant="ghost" aria-label={`Restore revision ${r.number}`} onClick={() => edit(r.number)}>
                            Restore
                          </Button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </Table>
            )}
          </Card>
          <Card title={`Compose file (revision ${data.latest.number})`} className="lg:col-span-2">
            <pre tabIndex={0} aria-label="Latest compose file" className="max-h-96 overflow-auto rounded-md bg-slate-100 p-3 font-mono text-xs dark:bg-slate-950">{data.latest.compose}</pre>
          </Card>
        </div>
      )}

      <Dialog open={confirmDown} title="Take down this stack?" onClose={() => setConfirmDown(false)}>
        <p className="text-sm">All containers and networks of the stack are removed. Named volumes keep their data unless you choose otherwise.</p>
        <label className="mt-3 flex items-center gap-2 text-sm">
          <input type="checkbox" className="size-4" checked={removeVolumes} onChange={(e) => setRemoveVolumes(e.target.checked)} />
          Also delete the stack's volumes and their data
        </label>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setConfirmDown(false)}>
            Cancel
          </Button>
          <Button variant="danger" busy={busy} onClick={() => { setConfirmDown(false); void run(() => api.post(`/stacks/${name}/down`, { remove_volumes: removeVolumes }), "Taking the stack down."); }}>
            Take down
          </Button>
        </div>
      </Dialog>
    </>
  );
}
