import { useState } from "react";
import { StackEditor, toInput, type VariableRow } from "../components/StackEditor";
import { Alert, Badge, Button, Card, PageHeader, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import type { Stack, StackEvaluation, StackException } from "../lib/types";
import { useData } from "../lib/useData";

export const statusTone = { new: "gray", deploying: "blue", deployed: "green", failed: "red", stopping: "blue", stopped: "gray" } as const;

export function StacksPage() {
  const { can } = useSession();
  const { navigate } = useRouter();
  const { data, error, loading } = useData(() => api.get<{ stacks: Stack[] }>("/stacks"), [], { refreshMs: 3000, live: ["containers", "jobs"] });
  return (
    <>
      <PageHeader
        title="Stacks"
        description="Multi-container applications from Compose files, deployed as revisions with automatic rollback."
        actions={can("containers.manage") ? <Button onClick={() => navigate("/stacks/new")}>New stack</Button> : undefined}
      />
      <Card>
        {loading && !data && <Spinner />}
        {error && <Alert>{error}</Alert>}
        {data && data.stacks.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">No stacks yet.</p>}
        {data && data.stacks.length > 0 && (
          <Table
            caption="Stacks"
            head={
              <tr>
                <th className={th}>Name</th>
                <th className={th}>Status</th>
                <th className={th}>Deployed</th>
                <th className={th}>Latest</th>
                <th className={th}>Updated</th>
              </tr>
            }
          >
            {data.stacks.map((s) => (
              <tr key={s.id}>
                <td className={td}>
                  <Link to={`/stacks/${s.name}`} className="font-medium text-brand-700 underline dark:text-brand-500">
                    {s.name}
                  </Link>
                </td>
                <td className={td}>
                  <Badge tone={statusTone[s.status]}>{s.status}</Badge>
                </td>
                <td className={td}>{s.deployed_revision ? `revision ${s.deployed_revision}` : "—"}</td>
                <td className={td}>revision {s.latest_revision}</td>
                <td className={td}>{formatDateTime(s.updated_at)}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}

const example = `services:
  web:
    image: nginx:1.27
    user: "101"
    mem_limit: 128m
    ports:
      - "127.0.0.1:8080:80"
`;

export function NewStackPage() {
  const { navigate } = useRouter();
  const [name, setName] = useState("");
  const [compose, setCompose] = useState(example);
  const [variables, setVariables] = useState<VariableRow[]>([]);
  const [exceptions, setExceptions] = useState<StackException[]>([]);
  const [evaluation, setEvaluation] = useState<StackEvaluation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const validName = /^[a-z0-9][a-z0-9-]{0,30}$/.test(name);

  const save = async (deploy: boolean) => {
    setBusy(true);
    setError(null);
    try {
      await api.post("/stacks", { name, compose, comment: "created", variables: toInput(variables), exceptions });
      if (deploy) await api.post(`/stacks/${name}/deploy`);
      navigate(`/stacks/${name}`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <p className="mb-2 text-sm">
        <Link to="/stacks" className="text-brand-700 underline dark:text-brand-500">
          ← All stacks
        </Link>
      </p>
      <PageHeader title="New stack" description="Paste, upload or import a Compose file. Unsupported options are reported with their line." />
      <Card className="mb-4">
        <div className="max-w-sm">
          <TextField label="Stack name" autoCapitalize="none" spellCheck={false} value={name} onChange={(e) => setName(e.target.value)} hint="Lowercase letters, digits and - (max. 31)" error={name && !validName ? "Invalid name" : undefined} />
        </div>
      </Card>
      <StackEditor
        stackName={validName ? name : ""}
        compose={compose}
        onCompose={setCompose}
        variables={variables}
        onVariables={setVariables}
        exceptions={exceptions}
        onExceptions={setExceptions}
        onEvaluation={setEvaluation}
      />
      <div className="mt-4 flex flex-wrap items-center gap-2">
        {error && (
          <div className="w-full">
            <Alert>{error}</Alert>
          </div>
        )}
        <Button busy={busy} disabled={!validName || !evaluation?.deployable} onClick={() => save(true)}>
          Create and deploy
        </Button>
        <Button variant="secondary" busy={busy} disabled={!validName || !evaluation?.deployable} onClick={() => save(false)}>
          Create only
        </Button>
      </div>
    </>
  );
}
