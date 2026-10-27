import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Alert, Badge, Button, Card, PageHeader, SelectField, TextField } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import type { ContainerSpec, NetworkSummary, PolicyEvaluation } from "../lib/types";
import { useData } from "../lib/useData";

interface Form {
  name: string;
  image: string;
  command: string;
  env: string;
  user: string;
  ports: string;
  mounts: string;
  network: string;
  restart: string;
  memoryMiB: string;
  privileged: boolean;
  capAdd: string;
  devices: string;
  hostPid: boolean;
  start: boolean;
}

const initial: Form = {
  name: "",
  image: "",
  command: "",
  env: "",
  user: "",
  ports: "",
  mounts: "",
  network: "",
  restart: "unless-stopped",
  memoryMiB: "256",
  privileged: false,
  capAdd: "",
  devices: "",
  hostPid: false,
  start: true,
};

const lines = (s: string) =>
  s
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
const list = (s: string) =>
  s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

/** toSpec converts the form; parse problems are returned for display. */
function toSpec(f: Form): { spec: ContainerSpec; problems: string[] } {
  const problems: string[] = [];
  const spec: ContainerSpec = { name: f.name.trim(), image: f.image.trim(), restart_policy: f.restart };
  if (f.command.trim()) spec.cmd = lines(f.command);
  if (f.user.trim()) spec.user = f.user.trim();
  const env = lines(f.env).map((l) => {
    const i = l.indexOf("=");
    if (i <= 0) problems.push(`Environment line "${l}" must be NAME=value`);
    return { name: l.slice(0, Math.max(i, 0)), value: l.slice(i + 1) };
  });
  if (env.length) spec.env = env;
  const ports = lines(f.ports).map((l) => {
    // [ip:]host:container[/proto]
    const m = /^(?:([0-9a-fA-F.:]+):)?(\d+):(\d+)(?:\/(tcp|udp))?$/.exec(l);
    if (!m) {
      problems.push(`Port "${l}" must look like 8080:80, 127.0.0.1:8080:80 or 53:53/udp`);
      return { host_port: 0, container_port: 0 };
    }
    return { host_ip: m[1], host_port: Number(m[2]), container_port: Number(m[3]), protocol: m[4] };
  });
  if (ports.length) spec.ports = ports;
  const mounts = lines(f.mounts).map((l) => {
    // volume:name:/target[:ro] | bind:/host:/target[:ro] | tmpfs:/target
    const [type = "", a = "", b = "", ro] = l.split(":");
    if (type === "tmpfs") return { type, target: a };
    if (type !== "volume" && type !== "bind") problems.push(`Mount "${l}" must start with volume:, bind: or tmpfs:`);
    return { type, source: a, target: b, read_only: ro === "ro" };
  });
  if (mounts.length) spec.mounts = mounts;
  if (f.network) spec.network_mode = f.network;
  const mib = Number(f.memoryMiB || "0");
  if (!Number.isFinite(mib) || mib < 0) problems.push("Memory limit must be a number of MiB");
  else if (mib > 0) spec.memory_bytes = Math.round(mib * 1024 * 1024);
  if (f.privileged) spec.privileged = true;
  if (f.capAdd.trim()) spec.cap_add = list(f.capAdd);
  if (f.devices.trim()) spec.devices = list(f.devices);
  if (f.hostPid) spec.pid_mode = "host";
  return { spec, problems };
}

export function CreateContainerPage() {
  const { can } = useSession();
  const { navigate } = useRouter();
  const [form, setForm] = useState<Form>(initial);
  const [evaluation, setEvaluation] = useState<PolicyEvaluation | null>(null);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [approved, setApproved] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const networks = useData(() => api.get<{ networks: NetworkSummary[] }>("/networks"), []);
  const { spec, problems } = useMemo(() => toSpec(form), [form]);
  const set = <K extends keyof Form>(k: K) => (v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));

  // Live policy evaluation (debounced).
  useEffect(() => {
    if (!spec.name || !spec.image || problems.length) {
      setEvaluation(null);
      return;
    }
    const t = setTimeout(async () => {
      try {
        setEvaluation(await api.post<PolicyEvaluation>("/containers/validate", spec));
      } catch (err) {
        setError(errorMessage(err));
      }
    }, 300);
    return () => clearTimeout(t);
  }, [spec, problems.length]);

  const blocking = evaluation?.violations.filter((v) => !(v.exemptible && approved[v.rule] && (reasons[v.rule] ?? "").trim().length >= 10)) ?? [];
  const canSubmit = !!evaluation?.valid && blocking.length === 0 && problems.length === 0;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const rules = [...new Set(evaluation?.violations.map((v) => v.rule) ?? [])];
      const exceptions = rules.filter((r) => approved[r]).map((rule) => ({ rule, reason: (reasons[rule] ?? "").trim() }));
      await api.post("/containers", { spec, exceptions, start: form.start });
      navigate(`/containers/${encodeURIComponent(spec.name)}`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const rules = [...new Map(evaluation?.violations.map((v) => [v.rule, v]) ?? []).values()];
  return (
    <>
      <p className="mb-2 text-sm">
        <Link to="/containers" className="text-brand-700 underline dark:text-brand-500">
          ← All containers
        </Link>
      </p>
      <PageHeader title="New container" description="Dangerous settings are rejected unless an owner approves an exception with a reason." />
      <form onSubmit={submit} className="grid grid-cols-1 gap-4 lg:grid-cols-3" noValidate>
        <div className="space-y-4 lg:col-span-2">
          <Card title="Basics">
            <div className="grid gap-4 sm:grid-cols-2">
              <TextField label="Name" required autoCapitalize="none" spellCheck={false} value={form.name} onChange={(e) => set("name")(e.target.value)} />
              <TextField label="Image" required autoCapitalize="none" spellCheck={false} placeholder="e.g. nginx:1.27" value={form.image} onChange={(e) => set("image")(e.target.value)} hint="Pull it first under Images if it is not on the host." />
              <TextField label="User (optional)" placeholder="e.g. 1000:1000" value={form.user} onChange={(e) => set("user")(e.target.value)} />
              <TextField label="Memory limit (MiB, 0 = none)" inputMode="numeric" value={form.memoryMiB} onChange={(e) => set("memoryMiB")(e.target.value)} />
              <SelectField label="Restart policy" value={form.restart} onChange={(e) => set("restart")(e.target.value)}>
                {["unless-stopped", "on-failure", "always", "no"].map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </SelectField>
              <SelectField label="Network" value={form.network} onChange={(e) => set("network")(e.target.value)}>
                <option value="">bridge (default)</option>
                <option value="none">none (no network)</option>
                {networks.data?.networks
                  .filter((n) => !n.built_in)
                  .map((n) => (
                    <option key={n.id} value={n.name}>
                      {n.name}
                      {n.internal ? " (internal)" : ""}
                    </option>
                  ))}
                <option value="host">host (requires an exception)</option>
              </SelectField>
            </div>
          </Card>
          <Card title="Command, environment, ports and storage">
            <div className="grid gap-4 sm:grid-cols-2">
              <TextAreaField label="Command (one argument per line)" value={form.command} onChange={set("command")} placeholder={"sh\n-c\necho hello"} />
              <TextAreaField label="Environment (NAME=value per line)" value={form.env} onChange={set("env")} placeholder="TZ=Europe/Berlin" />
              <TextAreaField label="Ports (one per line)" value={form.ports} onChange={set("ports")} placeholder={"127.0.0.1:8080:80\n53:53/udp"} />
              <TextAreaField label="Mounts (one per line)" value={form.mounts} onChange={set("mounts")} placeholder={"volume:app-data:/data\nbind:/srv/kernhaven/media:/media:ro\ntmpfs:/tmp"} />
            </div>
          </Card>
          <Card title="Advanced (security-relevant)">
            <div className="grid gap-4 sm:grid-cols-2">
              <TextField label="Add capabilities (comma separated)" value={form.capAdd} onChange={(e) => set("capAdd")(e.target.value)} />
              <TextField label="Host devices (comma separated)" value={form.devices} onChange={(e) => set("devices")(e.target.value)} />
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" className="size-4" checked={form.privileged} onChange={(e) => set("privileged")(e.target.checked)} />
                Privileged mode
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" className="size-4" checked={form.hostPid} onChange={(e) => set("hostPid")(e.target.checked)} />
                Host PID namespace
              </label>
            </div>
          </Card>
        </div>

        <div className="space-y-4">
          <Card title="Policy check">
            <div aria-live="polite" className="space-y-3 text-sm">
              {problems.map((p) => (
                <Alert key={p}>{p}</Alert>
              ))}
              {!evaluation && problems.length === 0 && <p className="text-slate-600 dark:text-slate-400">Enter a name and an image to check the configuration.</p>}
              {evaluation && !evaluation.valid && evaluation.errors.map((e) => <Alert key={e}>{e}</Alert>)}
              {evaluation?.valid && evaluation.violations.length === 0 && <Alert kind="success">No policy violations.</Alert>}
              {rules.map((v) => (
                <div key={v.rule} className="rounded-md border border-red-300 p-3 dark:border-red-800">
                  <p className="font-medium text-red-800 dark:text-red-300">
                    Violation: {v.rule}
                  </p>
                  <p>{v.message}</p>
                  {!v.exemptible && <p className="mt-1 font-medium">This can never be allowed.</p>}
                  {v.exemptible && can("policy.exceptions") && (
                    <div className="mt-2 space-y-2">
                      <label className="flex items-center gap-2">
                        <input type="checkbox" className="size-4" checked={!!approved[v.rule]} onChange={(e) => setApproved({ ...approved, [v.rule]: e.target.checked })} />
                        Approve an exception (audited)
                      </label>
                      {approved[v.rule] && (
                        <TextField label="Reason (at least 10 characters)" value={reasons[v.rule] ?? ""} onChange={(e) => setReasons({ ...reasons, [v.rule]: e.target.value })} />
                      )}
                    </div>
                  )}
                  {v.exemptible && !can("policy.exceptions") && <p className="mt-1 text-xs">Only an owner can approve an exception.</p>}
                </div>
              ))}
              {evaluation?.warnings.map((w) => (
                <p key={w.rule + w.message} className="flex gap-2">
                  <Badge tone="amber">warning</Badge>
                  <span>{w.message}</span>
                </p>
              ))}
            </div>
          </Card>
          <Card>
            {error && (
              <div className="mb-3">
                <Alert>{error}</Alert>
              </div>
            )}
            <label className="mb-3 flex items-center gap-2 text-sm">
              <input type="checkbox" className="size-4" checked={form.start} onChange={(e) => set("start")(e.target.checked)} />
              Start after creating
            </label>
            <Button type="submit" className="w-full" busy={busy} disabled={!canSubmit}>
              Create container
            </Button>
          </Card>
        </div>
      </form>
    </>
  );
}

function TextAreaField({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  const id = `ta-${label.replace(/\W+/g, "-").toLowerCase()}`;
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
      </label>
      <textarea
        id={id}
        rows={4}
        spellCheck={false}
        className="block w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-900 placeholder:text-slate-500 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}
