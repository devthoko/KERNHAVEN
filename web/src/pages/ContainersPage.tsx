import { useState } from "react";
import { AgentError, StateBadge } from "../components/DockerBits";
import { Alert, Button, Card, PageHeader, Spinner, Table, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { containerName } from "../lib/format";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import type { ContainerSummary } from "../lib/types";
import { useData } from "../lib/useData";

export function ports(c: ContainerSummary): string {
  return (
    c.ports
      .filter((p) => p.public_port)
      .map((p) => `${p.ip && p.ip !== "0.0.0.0" && p.ip !== "::" ? `${p.ip}:` : ""}${p.public_port}→${p.private_port}/${p.type}`)
      .filter((v, i, a) => a.indexOf(v) === i)
      .join(", ") || "—"
  );
}

export function ContainersPage() {
  const { can } = useSession();
  const { navigate } = useRouter();
  const { data, error, loading, reload } = useData(() => api.get<{ containers: ContainerSummary[] }>("/containers"), [], { refreshMs: 3000, live: ["containers"] });
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const act = async (c: ContainerSummary, action: string) => {
    setBusy(c.id + action);
    setActionError(null);
    try {
      await api.post(`/containers/${encodeURIComponent(containerName(c))}/${action}`);
      await reload();
    } catch (err) {
      setActionError(`${containerName(c)}: ${errorMessage(err)}`);
    } finally {
      setBusy(null);
    }
  };

  const sorted = data?.containers.slice().sort((a, b) => containerName(a).localeCompare(containerName(b))) ?? [];
  return (
    <>
      <PageHeader
        title="Containers"
        description="All containers on this host. Every change goes through the host agent and is audited."
        actions={can("containers.manage") ? <Button onClick={() => navigate("/containers/new")}>New container</Button> : undefined}
      />
      {actionError && (
        <div className="mb-4">
          <Alert>{actionError}</Alert>
        </div>
      )}
      <Card>
        {loading && !data && <Spinner />}
        {error && <AgentError message={error} />}
        {data && sorted.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">No containers yet.</p>}
        {sorted.length > 0 && (
          <Table
            caption="Containers"
            head={
              <tr>
                <th className={th}>Name</th>
                <th className={th}>State</th>
                <th className={th}>Image</th>
                <th className={th}>Ports</th>
                {can("containers.operate") && (
                  <th className={th}>
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            }
          >
            {sorted.map((c) => {
              const name = containerName(c);
              const running = c.state === "running";
              return (
                <tr key={c.id}>
                  <td className={td}>
                    <Link to={`/containers/${encodeURIComponent(name)}`} className="font-medium text-brand-700 underline dark:text-brand-500">
                      {name}
                    </Link>
                    <div className="text-xs text-slate-600 dark:text-slate-400">{c.status}</div>
                  </td>
                  <td className={td}>
                    <StateBadge state={c.state} />
                  </td>
                  <td className={`${td} max-w-64 truncate`} title={c.image}>
                    {c.image}
                  </td>
                  <td className={td}>{ports(c)}</td>
                  {can("containers.operate") && (
                    <td className={`${td} text-right`}>
                      <div className="flex justify-end gap-1">
                        {c.state === "paused" ? (
                          <Button variant="ghost" busy={busy === c.id + "unpause"} onClick={() => act(c, "unpause")} aria-label={`Resume ${name}`}>
                            Resume
                          </Button>
                        ) : running ? (
                          <>
                            <Button variant="ghost" busy={busy === c.id + "restart"} onClick={() => act(c, "restart")} aria-label={`Restart ${name}`}>
                              Restart
                            </Button>
                            <Button variant="ghost" busy={busy === c.id + "stop"} onClick={() => act(c, "stop")} aria-label={`Stop ${name}`}>
                              Stop
                            </Button>
                          </>
                        ) : (
                          <Button variant="ghost" busy={busy === c.id + "start"} onClick={() => act(c, "start")} aria-label={`Start ${name}`}>
                            Start
                          </Button>
                        )}
                      </div>
                    </td>
                  )}
                </tr>
              );
            })}
          </Table>
        )}
      </Card>
    </>
  );
}
