import { useEffect, useRef, useState } from "react";
import { AgentError, ConfirmByName, StateBadge } from "../components/DockerBits";
import { Alert, BackLink, Badge, Button, Card, PageHeader, SelectField, Spinner } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import type { ContainerDetail, LogLine } from "../lib/types";
import { useData } from "../lib/useData";
import { Console } from "./ContainerConsole";

const MAX_FOLLOW_LINES = 2000;

/** useFollow streams new log lines while on (M6b); null when off or unsupported. */
function useFollow(id: string, on: boolean): { lines: LogLine[]; ended: boolean } | null {
  const [state, setState] = useState<{ lines: LogLine[]; ended: boolean }>({ lines: [], ended: false });
  useEffect(() => {
    if (!on || typeof EventSource === "undefined") return;
    setState({ lines: [], ended: false });
    const es = new EventSource(`/api/v1/containers/${encodeURIComponent(id)}/logs/stream`);
    es.addEventListener("log", (e) => {
      const { stream, text } = JSON.parse((e as MessageEvent).data) as { stream: "stdout" | "stderr"; text: string };
      const add = text.replace(/\n$/, "").split("\n").map((t) => ({ stream, text: t }) as LogLine);
      setState((st) => ({ ended: false, lines: [...st.lines, ...add].slice(-MAX_FOLLOW_LINES) }));
    });
    es.addEventListener("end", () => {
      es.close();
      setState((st) => ({ ...st, ended: true }));
    });
    return () => es.close();
  }, [id, on]);
  return on && typeof EventSource !== "undefined" ? state : null;
}

function Logs({ id }: { id: string }) {
  const [tail, setTail] = useState("200");
  const [follow, setFollow] = useState(true);
  const [timestamps, setTimestamps] = useState(false);
  const streaming = useFollow(id, follow && !timestamps);
  const { data, error } = useData(
    () => api.get<{ lines: LogLine[]; truncated: boolean }>(`/containers/${encodeURIComponent(id)}/logs?tail=${tail}&timestamps=${timestamps}`),
    [id, tail, timestamps, follow],
    { refreshMs: 2000, shouldPoll: () => follow && streaming === null },
  );
  const lines = streaming ? streaming.lines : data?.lines;
  const box = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines, follow]);
  return (
    <Card title="Logs">
      <div className="mb-3 flex flex-wrap items-end gap-4">
        <div className="w-36">
          <SelectField label="Lines" value={tail} disabled={streaming !== null} onChange={(e) => setTail(e.target.value)}>
            {["100", "200", "1000", "5000"].map((n) => (
              <option key={n} value={n}>
                last {n}
              </option>
            ))}
          </SelectField>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" className="size-4" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
          Follow (live)
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" className="size-4" checked={timestamps} onChange={(e) => setTimestamps(e.target.checked)} />
          Timestamps
        </label>
      </div>
      {error && !streaming && <Alert>{error}</Alert>}
      {data?.truncated && !streaming && <Alert kind="info">Output truncated to 2 MB; choose fewer lines.</Alert>}
      {streaming?.ended && <Alert kind="info">The log stream ended (the container stopped or 30 minutes passed). Turn Follow off and on to continue.</Alert>}
      <pre
        ref={box}
        tabIndex={0}
        aria-label="Container log output"
        className="max-h-[28rem] overflow-auto rounded-md bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-100"
      >
        {lines?.length
          ? lines.map((l, i) => (
              <div key={i} className={l.stream === "stderr" ? "text-amber-300" : undefined}>
                {l.text}
              </div>
            ))
          : "No log output."}
      </pre>
    </Card>
  );
}

export function ContainerDetailPage({ id }: { id: string }) {
  const { can } = useSession();
  const { navigate } = useRouter();
  const { data: c, error, loading, reload } = useData(() => api.get<ContainerDetail>(`/containers/${encodeURIComponent(id)}`), [id], { refreshMs: 3000, live: ["containers"] });
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const [removeVolumes, setRemoveVolumes] = useState(false);

  const act = async (action: string) => {
    setBusy(action);
    setActionError(null);
    try {
      await api.post(`/containers/${encodeURIComponent(id)}/${action}`);
      await reload();
    } catch (err) {
      setActionError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  if (loading && !c) return <Spinner />;
  if (!c) return error ? <AgentError message={error} /> : <Alert>Container not found.</Alert>;
  const exceptions = c.labels["io.kernhaven.policy.exceptions"]?.split(",").filter(Boolean) ?? [];

  return (
    <>
      <BackLink to="/containers">All containers</BackLink>
      <PageHeader
        title={c.name}
        description={c.image}
        actions={
          <>
            {can("containers.operate") &&
              (c.status === "paused" ? (
                <Button variant="secondary" busy={busy === "unpause"} onClick={() => act("unpause")}>
                  Resume
                </Button>
              ) : c.running ? (
                <>
                  <Button variant="secondary" busy={busy === "restart"} onClick={() => act("restart")}>
                    Restart
                  </Button>
                  <Button variant="secondary" busy={busy === "pause"} onClick={() => act("pause")}>
                    Pause
                  </Button>
                  <Button variant="secondary" busy={busy === "stop"} onClick={() => act("stop")}>
                    Stop
                  </Button>
                </>
              ) : (
                <Button busy={busy === "start"} onClick={() => act("start")}>
                  Start
                </Button>
              ))}
            {can("containers.manage") && (
              <Button variant="danger" onClick={() => setRemoving(true)}>
                Remove
              </Button>
            )}
          </>
        }
      />
      {actionError && (
        <div className="mb-4">
          <Alert>{actionError}</Alert>
        </div>
      )}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Status">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-slate-600 dark:text-slate-400">State</dt>
            <dd>
              <StateBadge state={c.status} /> {c.health && <Badge tone={c.health === "healthy" ? "green" : "amber"}>{c.health}</Badge>}
            </dd>
            <dt className="text-slate-600 dark:text-slate-400">Started</dt>
            <dd>{c.started_at.startsWith("0001") ? "—" : formatDateTime(c.started_at)}</dd>
            {!c.running && (
              <>
                <dt className="text-slate-600 dark:text-slate-400">Exit code</dt>
                <dd>{c.exit_code}</dd>
              </>
            )}
            <dt className="text-slate-600 dark:text-slate-400">Restart policy</dt>
            <dd>{c.restart_policy || "no"}</dd>
            <dt className="text-slate-600 dark:text-slate-400">ID</dt>
            <dd className="break-all font-mono text-xs">{c.id.slice(0, 24)}</dd>
          </dl>
        </Card>
        <Card title="Security">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-slate-600 dark:text-slate-400">User</dt>
            <dd>{c.user || <span className="text-amber-800 dark:text-amber-300">root (image default)</span>}</dd>
            <dt className="text-slate-600 dark:text-slate-400">Privileged</dt>
            <dd>{c.privileged ? <Badge tone="red">yes</Badge> : "no"}</dd>
            <dt className="text-slate-600 dark:text-slate-400">Network</dt>
            <dd>{c.network_mode}</dd>
            <dt className="text-slate-600 dark:text-slate-400">Added capabilities</dt>
            <dd>{c.cap_add.length ? c.cap_add.join(", ") : "none"}</dd>
            <dt className="text-slate-600 dark:text-slate-400">Policy exceptions</dt>
            <dd>{exceptions.length ? exceptions.map((x) => <Badge key={x} tone="amber">{x}</Badge>) : "none"}</dd>
            <dt className="text-slate-600 dark:text-slate-400">Managed by Kernhaven</dt>
            <dd>{c.labels["io.kernhaven.managed"] === "true" ? `yes (created by ${c.labels["io.kernhaven.created_by"] || "?"})` : "no (created outside Kernhaven)"}</dd>
          </dl>
          {c.mounts.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs">
              {c.mounts.map((m) => (
                <li key={m.destination} className="break-all font-mono">
                  {m.type}: {m.source} → {m.destination} {m.rw ? "" : "(read-only)"}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <div className="lg:col-span-2">{can("containers.operate") ? <Logs id={id} /> : <Alert kind="info">Viewing logs requires the operator role, because logs often contain secrets.</Alert>}</div>
        {can("containers.exec") && c.running && c.labels["io.kernhaven.managed"] === "true" && (
          <div className="lg:col-span-2">
            <Console id={id} name={c.name} />
          </div>
        )}
      </div>
      <ConfirmByName
        open={removing}
        title="Remove container"
        name={c.name}
        action="Remove container"
        onClose={() => setRemoving(false)}
        onConfirm={async () => {
          await api.del(`/containers/${encodeURIComponent(id)}?force=true&volumes=${removeVolumes}`);
          navigate("/containers");
        }}
      >
        <p className="text-sm">The container is stopped if needed and removed. Named volumes are kept unless you choose otherwise.</p>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" className="size-4" checked={removeVolumes} onChange={(e) => setRemoveVolumes(e.target.checked)} />
          Also remove its anonymous volumes
        </label>
      </ConfirmByName>
    </>
  );
}
