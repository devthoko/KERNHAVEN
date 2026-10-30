import { useState, type FormEvent, type ReactNode } from "react";
import { AgentError, ConfirmByName } from "../components/DockerBits";
import { Alert, Badge, Button, Card, PageHeader, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { useSession } from "../lib/session";
import type { NetworkSummary, VolumeSummary } from "../lib/types";
import { useData } from "../lib/useData";

function CreateForm({ label, onCreate, extra }: { label: string; onCreate: (name: string) => Promise<void>; extra?: ReactNode }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onCreate(name.trim());
      setName("");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="mb-4 space-y-2" noValidate>
      {error && <Alert>{error}</Alert>}
      <div className="grid gap-3 sm:grid-cols-[1fr_auto] sm:items-end">
        <TextField label={label} autoCapitalize="none" spellCheck={false} value={name} onChange={(e) => setName(e.target.value)} />
        <Button type="submit" busy={busy} disabled={!name.trim()}>
          Create
        </Button>
      </div>
      {extra}
    </form>
  );
}

export function VolumesPage() {
  const { can } = useSession();
  const { data, error, loading, reload } = useData(() => api.get<{ volumes: VolumeSummary[] }>("/volumes"), []);
  const [removing, setRemoving] = useState<string | null>(null);
  return (
    <>
      <PageHeader title="Volumes" description="Named Docker volumes. Volumes in use by a container cannot be removed." />
      <Card>
        {can("containers.manage") && <CreateForm label="New volume name" onCreate={async (name) => { await api.post("/volumes", { name }); await reload(); }} />}
        {loading && !data && <Spinner />}
        {error && <AgentError message={error} />}
        {data && data.volumes.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">No volumes.</p>}
        {data && data.volumes.length > 0 && (
          <Table
            caption="Volumes"
            head={
              <tr>
                <th className={th}>Name</th>
                <th className={th}>Driver</th>
                <th className={th}>Created</th>
                {can("containers.manage") && (
                  <th className={th}>
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            }
          >
            {data.volumes.map((v) => (
              <tr key={v.name}>
                <td className={`${td} max-w-80 truncate font-medium`} title={v.name}>
                  {v.name} {v.labels["io.kernhaven.managed"] === "true" && <Badge tone="blue">Kernhaven</Badge>}
                </td>
                <td className={td}>{v.driver}</td>
                <td className={td}>{formatDateTime(v.created_at)}</td>
                {can("containers.manage") && (
                  <td className={`${td} text-right`}>
                    <Button variant="ghost-danger" aria-label={`Remove volume ${v.name}`} onClick={() => setRemoving(v.name)}>
                      Remove
                    </Button>
                  </td>
                )}
              </tr>
            ))}
          </Table>
        )}
      </Card>
      {removing && (
        <ConfirmByName open title="Remove volume" name={removing} action="Remove volume and its data" onClose={() => setRemoving(null)}
          onConfirm={async () => { await api.del(`/volumes/${encodeURIComponent(removing)}`); setRemoving(null); await reload(); }}>
          <p className="text-sm">All data in this volume is deleted permanently.</p>
        </ConfirmByName>
      )}
    </>
  );
}

export function NetworksPage() {
  const { can } = useSession();
  const { data, error, loading, reload } = useData(() => api.get<{ networks: NetworkSummary[] }>("/networks"), []);
  const [internal, setInternal] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  return (
    <>
      <PageHeader title="Networks" description="Bridge networks connect containers. Internal networks have no outside access." />
      <Card>
        {can("containers.manage") && (
          <CreateForm
            label="New network name"
            onCreate={async (name) => { await api.post("/networks", { name, internal }); await reload(); }}
            extra={
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" className="size-4" checked={internal} onChange={(e) => setInternal(e.target.checked)} />
                Internal (no access to other networks or the internet)
              </label>
            }
          />
        )}
        {loading && !data && <Spinner />}
        {error && <AgentError message={error} />}
        {data && (
          <Table
            caption="Networks"
            head={
              <tr>
                <th className={th}>Name</th>
                <th className={th}>Driver</th>
                <th className={th}>Containers</th>
                <th className={th}>Type</th>
                {can("containers.manage") && (
                  <th className={th}>
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            }
          >
            {data.networks.map((n) => (
              <tr key={n.id}>
                <td className={`${td} font-medium`}>{n.name}</td>
                <td className={td}>{n.driver}</td>
                <td className={td}>{n.containers}</td>
                <td className={td}>
                  {n.built_in ? <Badge tone="gray">Built-in</Badge> : n.internal ? <Badge tone="blue">Internal</Badge> : <Badge tone="green">Bridge</Badge>}
                </td>
                {can("containers.manage") && (
                  <td className={`${td} text-right`}>
                    {!n.built_in && (
                      <Button variant="ghost-danger" aria-label={`Remove network ${n.name}`} onClick={() => setRemoving(n.name)}>
                        Remove
                      </Button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </Table>
        )}
      </Card>
      {removing && (
        <ConfirmByName open title="Remove network" name={removing} action="Remove network" onClose={() => setRemoving(null)}
          onConfirm={async () => { await api.del(`/networks/${encodeURIComponent(removing)}`); setRemoving(null); await reload(); }}>
          <p className="text-sm">Networks with connected containers cannot be removed.</p>
        </ConfirmByName>
      )}
    </>
  );
}
