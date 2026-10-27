import { useState } from "react";
import { appStatusTone, changedValues, DisclosureView, FieldInput, initialValues } from "../components/AppBits";
import { Alert, Badge, Button, Card, Dialog, PageHeader, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import type { InstalledAppDetail } from "../lib/types";
import { useData } from "../lib/useData";
import { webURL } from "./AppsPage";

const link = "text-brand-700 underline dark:text-brand-500";

export function AppDetailPage({ name }: { name: string }) {
  const { can } = useSession();
  const { navigate, search } = useRouter();
  const { data, error, loading, reload } = useData(() => api.get<InstalledAppDetail>(`/apps/${encodeURIComponent(name)}`), [name], { refreshMs: 3000 });
  const [job, setJob] = useState<number | null>(() => Number(search.get("job")) || null);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  const [updating, setUpdating] = useState(false);
  const [newValues, setNewValues] = useState<Record<string, string> | null>(null);
  const [approve, setApprove] = useState(false);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [deleteData, setDeleteData] = useState(false);
  const [password, setPassword] = useState("");
  const [removeError, setRemoveError] = useState<string | null>(null);

  if (loading && !data) return <Spinner />;
  if (!data) return <Alert>{error ?? "App not found."}</Alert>;
  const manage = can("apps.manage");
  const busyState = data.status === "deploying" || data.status === "stopping";
  const up = data.update;
  const values = newValues ?? initialValues(up?.new_fields ?? []);

  const update = async () => {
    setBusy(true);
    setNotice(null);
    try {
      const res = await api.post<{ job_id: number }>(`/apps/${name}/update`, { values: changedValues(values), approve_exceptions: approve });
      setJob(res.job_id);
      setUpdating(false);
      setNotice({ kind: "success", text: `Updating to ${up?.to}. The data is saved first; a failed update is rolled back automatically.` });
      await reload();
    } catch (err) {
      setNotice({ kind: "error", text: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    setBusy(true);
    setRemoveError(null);
    try {
      await api.post(`/apps/${name}/remove`, { delete_data: deleteData, password: deleteData ? password : "" });
      navigate("/apps");
    } catch (err) {
      setRemoveError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <>
      <p className="mb-2 text-sm">
        <Link to="/apps" className={link}>
          ← Installed apps
        </Link>
      </p>
      <PageHeader
        title={data.name}
        description={`${data.app_name}${data.version ? ` ${data.version}` : ""} · from ${data.source_name}`}
        actions={
          <>
            {data.web_port > 0 && data.status === "deployed" && (
              <a href={webURL(data.web_port)} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-10 items-center rounded-md bg-brand-700 px-4 py-2 text-sm font-medium text-white hover:bg-brand-800">
                Open {data.app_name}
              </a>
            )}
            {manage && (
              <Button variant="danger" disabled={busyState} onClick={() => setRemoving(true)}>
                Remove
              </Button>
            )}
          </>
        }
      />
      {notice && (
        <div className="mb-4">
          <Alert kind={notice.kind}>{notice.text}</Alert>
        </div>
      )}
      {job && (
        <p className="mb-4 text-sm">
          <Link to={`/jobs/${job}`} className={link}>
            Follow job #{job}
          </Link>
        </p>
      )}
      {data.status === "failed" && data.status_message && (
        <div className="mb-4">
          <Alert>{data.status_message}</Alert>
        </div>
      )}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Status">
          <dl className="grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
            <dt className="text-slate-600 dark:text-slate-400">State</dt>
            <dd>
              <Badge tone={appStatusTone[data.status]}>{data.status}</Badge>
            </dd>
            <dt className="text-slate-600 dark:text-slate-400">Version</dt>
            <dd>{data.version || "not running yet"}</dd>
            <dt className="text-slate-600 dark:text-slate-400">Installed</dt>
            <dd>{formatDateTime(data.created_at)}</dd>
            <dt className="text-slate-600 dark:text-slate-400">Stack</dt>
            <dd>
              {can("containers.read") ? (
                <Link to={`/stacks/${data.name}`} className={link}>
                  {data.name}
                </Link>
              ) : (
                data.name
              )}
            </dd>
          </dl>
        </Card>
        <Card title="Configuration">
          {data.config.length === 0 ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">No settings.</p>
          ) : (
            <dl className="grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
              {data.config.map((v) => (
                <div key={v.name} className="contents">
                  <dt className="text-slate-600 dark:text-slate-400">{data.fields.find((f) => f.name === v.name)?.label ?? v.name}</dt>
                  <dd className="break-all">{v.secret ? <Badge>secret</Badge> : v.value}</dd>
                </div>
              ))}
            </dl>
          )}
        </Card>
        {up && (
          <Card title={`Update available: ${up.from} → ${up.to}`} className="lg:col-span-2">
            {up.images.length > 0 && (
              <div className="mb-3">
                <h3 className="mb-1 text-sm font-medium">Changed images</h3>
                <ul className="space-y-1 text-sm">
                  {up.images.map((i) => (
                    <li key={i.service} className="break-all">
                      <span className="font-medium">{i.service}</span>: <span className="font-mono text-xs">{i.from || "new"}</span> → <span className="font-mono text-xs">{i.to || "removed"}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {!updating ? (
              manage && (
                <Button disabled={busyState} onClick={() => setUpdating(true)}>
                  Review update
                </Button>
              )
            ) : (
              <div className="space-y-4">
                <DisclosureView disclosure={up.disclosure} />
                {up.new_fields.length > 0 && (
                  <div className="grid gap-4 sm:grid-cols-2">
                    {up.new_fields.map((f) => (
                      <FieldInput key={f.name} field={f} value={values[f.name] ?? ""} onChange={(v) => setNewValues({ ...values, [f.name]: v })} />
                    ))}
                  </div>
                )}
                {up.new_exceptions.length > 0 &&
                  (can("policy.exceptions") ? (
                    <label className="flex items-start gap-2 text-sm">
                      <input type="checkbox" className="mt-1 size-4" checked={approve} onChange={(e) => setApprove(e.target.checked)} />
                      <span>I approve the new policy exceptions of this version.</span>
                    </label>
                  ) : (
                    <Alert kind="warning">This version needs new policy exceptions; only an owner can update it.</Alert>
                  ))}
                <p className="text-sm text-slate-600 dark:text-slate-400">The app stops during the update. Its volumes are copied first and restored if the new version does not become healthy.</p>
                <div className="flex flex-wrap gap-2">
                  <Button busy={busy} disabled={!up.disclosure.installable || (up.new_exceptions.length > 0 && !approve)} onClick={update}>
                    Update to {up.to}
                  </Button>
                  <Button variant="ghost" onClick={() => setUpdating(false)}>
                    Cancel
                  </Button>
                </div>
              </div>
            )}
          </Card>
        )}
        <Card title="Versions" className="lg:col-span-2">
          <Table
            caption="Versions"
            head={
              <tr>
                <th className={th}>Revision</th>
                <th className={th}>Version</th>
                <th className={th}>Change</th>
                <th className={th}>By</th>
                <th className={th}>When</th>
              </tr>
            }
          >
            {data.versions.map((v) => (
              <tr key={v.revision}>
                <td className={td}>
                  {v.revision} {v.deployed && <Badge tone="green">running</Badge>}
                </td>
                <td className={td}>{v.version}</td>
                <td className={td}>{v.comment}</td>
                <td className={td}>{v.created_by}</td>
                <td className={td}>{formatDateTime(v.created_at)}</td>
              </tr>
            ))}
          </Table>
        </Card>
      </div>
      <Dialog open={removing} title={`Remove ${data.name}?`} onClose={() => setRemoving(false)}>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void remove();
          }}
        >
          {removeError && <Alert>{removeError}</Alert>}
          <fieldset className="space-y-2 text-sm">
            <legend className="mb-1 font-medium">Data</legend>
            <label className="flex items-start gap-2">
              <input type="radio" name="data" className="mt-1 size-4" checked={!deleteData} onChange={() => setDeleteData(false)} />
              <span>Keep the data. Installing the app again under the same name uses it.</span>
            </label>
            <label className="flex items-start gap-2">
              <input type="radio" name="data" className="mt-1 size-4" checked={deleteData} onChange={() => setDeleteData(true)} />
              <span>Delete the data permanently, including snapshots.</span>
            </label>
          </fieldset>
          {deleteData && <TextField label="Your password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />}
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setRemoving(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="danger" busy={busy} disabled={deleteData && password === ""}>
              {deleteData ? "Remove app and data" : "Remove app"}
            </Button>
          </div>
        </form>
      </Dialog>
    </>
  );
}
