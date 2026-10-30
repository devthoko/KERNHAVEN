import { useState } from "react";
import { Icon } from "../components/Icon";
import { JobStateBadge } from "../components/JobBits";
import { Alert, Badge, Button, Card, Dialog, DotBadge, PageHeader, SelectField, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatBytes, formatDateTime, formatRelative } from "../lib/format";
import { useSession } from "../lib/session";
import type { BackupPlan, BackupRepository, BackupRetention, BackupSnapshot, BackupTargetConfig, BackupTargetKind, Stack } from "../lib/types";
import { useData } from "../lib/useData";

const kindLabel: Record<BackupTargetKind, string> = { local: "Local disk", smb: "Network share (SMB)", sftp: "SFTP", s3: "S3-compatible" };

type Notice = { kind: "success" | "error"; text: string };

function destination(r: BackupRepository): string {
  const c = r.config;
  if (r.kind === "local") return c.path ?? "";
  if (r.kind === "sftp") return `${c.user}@${c.host}:${c.port ?? 22}${c.path}`;
  if (r.kind === "smb") return `\\\\${c.host}\\${c.share}${c.path ? `\\${c.path.replaceAll("/", "\\")}` : ""}`;
  return `${c.endpoint}/${c.bucket}/${c.prefix ?? ""}`;
}

function VerifyBadge({ ok, at, message }: { ok?: boolean; at?: string; message: string }) {
  if (ok === undefined) return <Badge tone="gray">Not checked</Badge>;
  return (
    <span title={message}>
      <DotBadge tone={ok ? "green" : "red"}>{ok ? "Intact" : "Damaged"}</DotBadge> <span className="text-xs text-slate-600 dark:text-slate-400">{formatRelative(at)}</span>
    </span>
  );
}

function RepositoryDialog({ open, onClose, onSaved }: { open: boolean; onClose: () => void; onSaved: (text: string) => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<BackupTargetKind>("local");
  const [cfg, setCfg] = useState<BackupTargetConfig>({ port: 22, path_style: true, region: "us-east-1" });
  const [secret, setSecret] = useState("");
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [connect, setConnect] = useState(false);
  const [scan, setScan] = useState<{ host_key: string; fingerprint: string } | null>(null);
  const [coreKey, setCoreKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (p: Partial<BackupTargetConfig>) => setCfg({ ...cfg, ...p });
  const config = (): BackupTargetConfig => {
    if (kind === "local") return { path: cfg.path };
    if (kind === "sftp") return { host: cfg.host, port: Number(cfg.port ?? 22), user: cfg.user, path: cfg.path, host_key: scan?.host_key ?? "" };
    if (kind === "smb") return { host: cfg.host, port: Number(cfg.port ?? 445), share: cfg.share, path: cfg.path || "", user: cfg.user, domain: cfg.domain || "" };
    return { endpoint: cfg.endpoint, region: cfg.region, bucket: cfg.bucket, prefix: cfg.prefix || undefined, access_key_id: cfg.access_key_id, path_style: !!cfg.path_style };
  };
  const save = async () => {
    setError(null);
    if (!connect && pass !== pass2) {
      setError("The passphrases do not match.");
      return;
    }
    setBusy(true);
    const sec = kind === "sftp" ? (secret ? { password: secret } : undefined) : kind === "smb" ? { password: secret } : kind === "s3" ? { secret_access_key: secret } : undefined;
    try {
      await api.post("/backup/repositories", { name, kind, config: config(), secret: sec, passphrase: pass, connect });
      onSaved(connect ? `Connected to ${name}.` : `${name} is ready. Keep the passphrase somewhere safe: without it no backup can be restored on another host.`);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} title="Add a repository" onClose={onClose}>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        {error && <Alert>{error}</Alert>}
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField label="Name" required value={name} onChange={(e) => setName(e.target.value)} />
          <SelectField
            label="Where"
            value={kind}
            onChange={(e) => {
              const k = e.target.value as BackupTargetKind;
              setKind(k);
              // Each protocol has its own default port.
              if (k === "smb" && (cfg.port === 22 || !cfg.port)) set({ port: 445 });
              if (k === "sftp" && (cfg.port === 445 || !cfg.port)) set({ port: 22 });
            }}
          >
            {(Object.keys(kindLabel) as BackupTargetKind[]).map((k) => (
              <option key={k} value={k}>
                {kindLabel[k]}
              </option>
            ))}
          </SelectField>
        </div>
        {kind === "local" && (
          <TextField
            label="Directory"
            hint="Must be inside a backup root listed in core.toml (backup.local_roots), for example on a USB disk."
            required
            spellCheck={false}
            value={cfg.path ?? ""}
            onChange={(e) => set({ path: e.target.value })}
          />
        )}
        {kind === "sftp" && (
          <div className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <TextField label="Server" required autoCapitalize="none" spellCheck={false} value={cfg.host ?? ""} onChange={(e) => {
                  set({ host: e.target.value });
                  setScan(null);
                }} />
              <TextField label="Port" type="number" min={1} max={65535} value={cfg.port ?? 22} onChange={(e) => set({ port: Number(e.target.value) })} />
              <TextField label="User" required autoCapitalize="none" value={cfg.user ?? ""} onChange={(e) => set({ user: e.target.value })} />
              <TextField label="Directory on the server" required spellCheck={false} value={cfg.path ?? ""} onChange={(e) => set({ path: e.target.value })} />
            </div>
            <div className="space-y-2">
              <Button
                variant="secondary"
                onClick={async () => {
                  setError(null);
                  try {
                    setScan(await api.post<{ host_key: string; fingerprint: string }>("/backup/sftp-scan", { host: cfg.host, port: Number(cfg.port ?? 22) }));
                  } catch (err) {
                    setError(errorMessage(err));
                  }
                }}
              >
                Read the server&apos;s host key
              </Button>
              {scan && (
                <Alert kind="warning">
                  Compare this fingerprint with the server (<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>) before saving: <code className="break-all">{scan.fingerprint}</code>
                </Alert>
              )}
            </div>
            <TextField
              label="Password (optional)"
              type="password"
              autoComplete="off"
              hint="Leave empty to sign in with Kernhaven's own key."
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
            {!secret && (
              <div className="space-y-1 text-sm">
                <Button variant="ghost" onClick={async () => setCoreKey((await api.get<{ public_key: string }>("/backup/sftp-key")).public_key)}>
                  Show Kernhaven&apos;s public key
                </Button>
                {coreKey && (
                  <p>
                    Add it to <code>~/.ssh/authorized_keys</code> of the user: <code className="block break-all rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{coreKey}</code>
                  </p>
                )}
              </div>
            )}
          </div>
        )}
        {kind === "smb" && (
          <div className="grid gap-4 sm:grid-cols-2">
            <p className="text-sm text-slate-600 sm:col-span-2 dark:text-slate-400">
              A shared folder on a NAS, a Windows PC or a Samba server. Kernhaven signs in with the account below and requires signed SMB 2 or 3; SMB 1 is not supported. The
              folder must exist.
            </p>
            <TextField label="Server" hint="Host name or IP address, for example nas.home.arpa" required autoCapitalize="none" spellCheck={false} value={cfg.host ?? ""} onChange={(e) => set({ host: e.target.value })} />
            <TextField label="Port" type="number" min={1} max={65535} value={String(cfg.port ?? 445)} onChange={(e) => set({ port: Number(e.target.value) })} />
            <TextField label="Share" hint="The share's name, for example backup" required autoCapitalize="none" spellCheck={false} value={cfg.share ?? ""} onChange={(e) => set({ share: e.target.value })} />
            <TextField label="Folder in the share (optional)" hint="For example kernhaven or homelab/kernhaven" autoCapitalize="none" spellCheck={false} value={cfg.path ?? ""} onChange={(e) => set({ path: e.target.value })} />
            <TextField label="User" required autoCapitalize="none" autoComplete="off" spellCheck={false} value={cfg.user ?? ""} onChange={(e) => set({ user: e.target.value })} />
            <TextField label="Domain or workgroup (optional)" autoCapitalize="none" spellCheck={false} value={cfg.domain ?? ""} onChange={(e) => set({ domain: e.target.value })} />
            <div className="sm:col-span-2">
              <TextField
                label="Share password"
                type="password"
                required
                autoComplete="new-password"
                hint="Stored encrypted on this server; it cannot be read back."
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
            </div>
          </div>
        )}
        {kind === "s3" && (
          <div className="grid gap-4 sm:grid-cols-2">
            <TextField label="Endpoint" hint="https://s3.example.com" required autoCapitalize="none" spellCheck={false} value={cfg.endpoint ?? ""} onChange={(e) => set({ endpoint: e.target.value })} />
            <TextField label="Region" value={cfg.region ?? ""} onChange={(e) => set({ region: e.target.value })} />
            <TextField label="Bucket" required autoCapitalize="none" value={cfg.bucket ?? ""} onChange={(e) => set({ bucket: e.target.value })} />
            <TextField label="Prefix (optional)" hint="For example kernhaven/" autoCapitalize="none" value={cfg.prefix ?? ""} onChange={(e) => set({ prefix: e.target.value })} />
            <TextField label="Access key ID" required autoComplete="off" value={cfg.access_key_id ?? ""} onChange={(e) => set({ access_key_id: e.target.value })} />
            <TextField label="Secret access key" type="password" required autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
            <label className="flex items-center gap-2 text-sm sm:col-span-2">
              <input type="checkbox" className="size-4" checked={!!cfg.path_style} onChange={(e) => set({ path_style: e.target.checked })} />
              Bucket in the path (most self-hosted services)
            </label>
          </div>
        )}
        <fieldset className="space-y-3 rounded-lg border border-slate-200 p-3 dark:border-slate-700">
          <legend className="px-1 text-sm font-medium">Encryption</legend>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" className="size-4" checked={connect} onChange={(e) => setConnect(e.target.checked)} />
            The target already holds a Kernhaven repository
          </label>
          <TextField
            label="Passphrase"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
            hint="At least 12 characters. Kernhaven does not store it; you need it to restore on a new host."
            value={pass}
            onChange={(e) => setPass(e.target.value)}
          />
          {!connect && <TextField label="Repeat the passphrase" type="password" autoComplete="new-password" required value={pass2} onChange={(e) => setPass2(e.target.value)} />}
        </fieldset>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" busy={busy} disabled={kind === "sftp" && !scan}>
            {connect ? "Connect" : "Create"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

const emptyRetention: BackupRetention = { keep_last: 3, keep_daily: 7, keep_weekly: 4, keep_monthly: 6 };

function PlanDialog({ plan, repos, stacks, open, onClose, onSaved }: { plan: BackupPlan | null; repos: BackupRepository[]; stacks: Stack[]; open: boolean; onClose: () => void; onSaved: (text: string) => void }) {
  const [name, setName] = useState(plan?.name ?? "");
  const [repo, setRepo] = useState(plan?.repo ?? repos[0]?.id ?? 0);
  const [schedule, setSchedule] = useState(plan?.schedule ?? "0 3 * * *");
  const [platform, setPlatform] = useState(plan?.platform ?? true);
  const [all, setAll] = useState(plan ? plan.stacks.join() === "*" : true);
  const [chosen, setChosen] = useState<string[]>(plan && plan.stacks.join() !== "*" ? plan.stacks : []);
  const [quiesce, setQuiesce] = useState(plan?.quiesce ?? true);
  const [enabled, setEnabled] = useState(plan?.enabled ?? true);
  const [ret, setRet] = useState<BackupRetention>(plan?.retention ?? emptyRetention);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const save = async () => {
    setBusy(true);
    setError(null);
    const body = { name, repo: Number(repo), schedule, platform, stacks: all ? ["*"] : chosen, quiesce, enabled, retention: ret };
    try {
      if (plan) await api.put(`/backup/plans/${plan.id}`, body);
      else await api.post("/backup/plans", body);
      onSaved(`${name} was saved.`);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} title={plan ? `Edit ${plan.name}` : "Add a plan"} onClose={onClose}>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        {error && <Alert>{error}</Alert>}
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField label="Name" required value={name} onChange={(e) => setName(e.target.value)} />
          <SelectField label="Repository" value={repo} onChange={(e) => setRepo(Number(e.target.value))}>
            {repos.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </SelectField>
          <TextField
            label="Schedule"
            hint="Cron: minute hour day month weekday (host time), or @daily, @weekly. 0 3 * * * is every night at 03:00."
            required
            spellCheck={false}
            value={schedule}
            onChange={(e) => setSchedule(e.target.value)}
          />
        </div>
        <fieldset className="space-y-2 text-sm">
          <legend className="font-medium">What</legend>
          <label className="flex items-center gap-2">
            <input type="checkbox" className="size-4" checked={platform} onChange={(e) => setPlatform(e.target.checked)} />
            Platform (settings, users, stacks, certificates — the database and its key)
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" className="size-4" checked={all} onChange={(e) => setAll(e.target.checked)} />
            The data of all stacks and apps
          </label>
          {!all && (
            <div className="flex flex-wrap gap-3 pl-6">
              {stacks.map((s) => (
                <label key={s.name} className="flex items-center gap-1">
                  <input
                    type="checkbox"
                    className="size-4"
                    checked={chosen.includes(s.name)}
                    onChange={(e) => setChosen(e.target.checked ? [...chosen, s.name] : chosen.filter((x) => x !== s.name))}
                  />
                  {s.name}
                </label>
              ))}
            </div>
          )}
          <label className="flex items-center gap-2">
            <input type="checkbox" className="size-4" checked={quiesce} onChange={(e) => setQuiesce(e.target.checked)} />
            Stop each stack while its data is copied (consistent; a short interruption)
          </label>
        </fieldset>
        <fieldset>
          <legend className="text-sm font-medium">Keep</legend>
          <div className="mt-1 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <TextField label="Last" type="number" min={0} value={ret.keep_last} onChange={(e) => setRet({ ...ret, keep_last: Number(e.target.value) })} />
            <TextField label="Daily" type="number" min={0} value={ret.keep_daily} onChange={(e) => setRet({ ...ret, keep_daily: Number(e.target.value) })} />
            <TextField label="Weekly" type="number" min={0} value={ret.keep_weekly} onChange={(e) => setRet({ ...ret, keep_weekly: Number(e.target.value) })} />
            <TextField label="Monthly" type="number" min={0} value={ret.keep_monthly} onChange={(e) => setRet({ ...ret, keep_monthly: Number(e.target.value) })} />
          </div>
        </fieldset>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" className="size-4" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" busy={busy}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function RestoreDialog({ repo, snapshot, onClose, onDone }: { repo: BackupRepository; snapshot: BackupSnapshot; onClose: () => void; onDone: (n: Notice) => void }) {
  const [stack, setStack] = useState(snapshot.stacks[0] ?? "");
  const [busy, setBusy] = useState(false);
  return (
    <Dialog open title="Restore a stack" onClose={onClose}>
      <div className="space-y-4 text-sm">
        <p>
          The stack&apos;s volumes are replaced with their state from {formatDateTime(snapshot.created_at)}. The stack is stopped meanwhile; its current data is kept until the restored stack runs
          healthy, and put back if anything fails.
        </p>
        <SelectField label="Stack" value={stack} onChange={(e) => setStack(e.target.value)}>
          {snapshot.stacks.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </SelectField>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="danger"
            busy={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const r = await api.post<{ job_id: number }>(`/backup/repositories/${repo.id}/snapshots/${snapshot.id}/restore`, { stack });
                onDone({ kind: "success", text: `Restoring ${stack} (job ${r.job_id}). Follow it on the Jobs page.` });
              } catch (err) {
                onDone({ kind: "error", text: errorMessage(err) });
              }
            }}
          >
            Restore {stack}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function Snapshots({ repo, manage, onNotice }: { repo: BackupRepository; manage: boolean; onNotice: (n: Notice) => void }) {
  const snaps = useData(() => api.get<{ snapshots: BackupSnapshot[] }>(`/backup/repositories/${repo.id}/snapshots`), [repo.id], { refreshMs: 15000 });
  const [restoring, setRestoring] = useState<BackupSnapshot | null>(null);
  if (!snaps.data) return snaps.error ? <Alert>{snaps.error}</Alert> : <Spinner />;
  if (snaps.data.snapshots.length === 0) return <p className="text-sm text-slate-600 dark:text-slate-400">No snapshots in {repo.name} yet.</p>;
  return (
    <>
      <Table
        caption={`Snapshots in ${repo.name}`}
        head={
          <tr>
            <th className={th}>Created</th>
            <th className={th}>Plan</th>
            <th className={th}>Contents</th>
            <th className={th}>Size</th>
            <th className={th}>Check</th>
            {manage && (
              <th className={th}>
                <span className="sr-only">Actions</span>
              </th>
            )}
          </tr>
        }
      >
        {snaps.data.snapshots.map((s) => (
          <tr key={s.id}>
            <td className={td} title={s.id}>
              {formatDateTime(s.created_at)}
            </td>
            <td className={td}>{s.plan || "—"}</td>
            <td className={td}>{[s.platform ? "platform" : "", ...s.stacks].filter(Boolean).join(", ")}</td>
            <td className={td}>{formatBytes(s.size)}</td>
            <td className={td}>
              <VerifyBadge ok={s.verify_ok} at={s.verified_at} message={s.verify_message} />
            </td>
            {manage && (
              <td className={td}>
                {s.stacks.length > 0 && (
                  <Button variant="ghost" onClick={() => setRestoring(s)}>
                    Restore… <span className="sr-only">from {formatDateTime(s.created_at)}</span>
                  </Button>
                )}
              </td>
            )}
          </tr>
        ))}
      </Table>
      {restoring && (
        <RestoreDialog
          repo={repo}
          snapshot={restoring}
          onClose={() => setRestoring(null)}
          onDone={(n) => {
            setRestoring(null);
            onNotice(n);
          }}
        />
      )}
    </>
  );
}

/** BackupsPage manages repositories, plans, snapshots and restores (AT-F14-01..06). */
/** GettingStarted shows the steps to the first backup until a plan exists. */
function GettingStarted({ steps }: { steps: { title: string; detail: string; done: boolean }[] }) {
  return (
    <Card title="Set up backups in three steps">
      <ol className="grid gap-4 md:grid-cols-3">
        {steps.map((s, i) => (
          <li key={s.title} className="flex gap-3">
            <span
              className={`inline-flex size-7 shrink-0 items-center justify-center rounded-full text-sm font-semibold ${
                s.done ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300" : "bg-slate-100 text-slate-700 dark:bg-white/10 dark:text-slate-200"
              }`}
            >
              {s.done ? <Icon name="check" className="size-4" /> : i + 1}
            </span>
            <span className="text-sm">
              <span className="block font-medium">
                {s.title}
                {s.done && <span className="sr-only"> (done)</span>}
              </span>
              <span className="text-slate-600 dark:text-slate-400">{s.detail}</span>
            </span>
          </li>
        ))}
      </ol>
    </Card>
  );
}

export function BackupsPage() {
  const { can } = useSession();
  const manage = can("backup.manage");
  const run = can("backup.run");
  const repos = useData(() => api.get<{ repositories: BackupRepository[] }>("/backup/repositories"), [], { refreshMs: 15000 });
  const plans = useData(() => api.get<{ plans: BackupPlan[] }>("/backup/plans"), [], { refreshMs: 5000 });
  const stacks = useData(() => api.get<{ stacks: Stack[] }>("/stacks"), []);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [addRepo, setAddRepo] = useState(false);
  const [editPlan, setEditPlan] = useState<BackupPlan | "new" | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  if (!repos.data || !plans.data) return repos.error || plans.error ? <Alert>{repos.error ?? plans.error}</Alert> : <Spinner />;
  const repoList = repos.data.repositories;
  const current = repoList.find((r) => r.id === selected) ?? repoList[0];
  const reload = () => {
    void repos.reload();
    void plans.reload();
  };
  const act = async (key: string, f: () => Promise<Notice>) => {
    setBusy(key);
    try {
      setNotice(await f());
    } catch (err) {
      setNotice({ kind: "error", text: errorMessage(err) });
    } finally {
      setBusy(null);
      reload();
    }
  };

  return (
    <>
      <PageHeader title="Backups" description="Encrypted copies of the platform and your apps' data, on a disk, a network share (SMB), an SFTP server or S3." />
      <div className="space-y-4">
        {notice && <Alert kind={notice.kind}>{notice.text}</Alert>}
        {plans.data.plans.length === 0 && (
          <GettingStarted
            steps={[
              { title: "Add a repository", detail: "Where backups go: a local disk, a network share (SMB), an SFTP server or S3. You choose a passphrase that encrypts everything.", done: repoList.length > 0 },
              { title: "Add a plan", detail: "What to back up (the platform, app data) and when; old snapshots are thinned out automatically.", done: false },
              { title: "Run it once", detail: "Start the plan by hand to check that it works, then keep the passphrase somewhere safe outside this server.", done: false },
            ]}
          />
        )}
        <Card
          title="Repositories"
          actions={
            manage && (
              <Button variant="secondary" onClick={() => setAddRepo(true)}>
                Add a repository
              </Button>
            )
          }
        >
          {repoList.length === 0 ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">No repository yet. Add one, then a plan that fills it.</p>
          ) : (
            <Table
              caption="Backup repositories"
              head={
                <tr>
                  <th className={th}>Name</th>
                  <th className={th}>Where</th>
                  <th className={th}>Snapshots</th>
                  <th className={th}>Last check</th>
                  <th className={th}>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              }
            >
              {repoList.map((r) => (
                <tr key={r.id}>
                  <td className={td}>{r.name}</td>
                  <td className={`${td} break-all`}>
                    {kindLabel[r.kind]} <span className="font-mono text-xs">{destination(r)}</span>
                  </td>
                  <td className={td}>
                    {r.snapshots} ({formatBytes(r.size)})
                  </td>
                  <td className={td}>
                    <VerifyBadge ok={r.verify_ok} at={r.verified_at} message={r.verify_message} />
                    {r.verify_ok === false && <div className="max-w-xs whitespace-normal text-xs text-red-700 dark:text-red-400">{r.verify_message}</div>}
                  </td>
                  <td className={td}>
                    <span className="flex gap-1">
                      <Button variant="ghost" onClick={() => setSelected(r.id)}>
                        Snapshots <span className="sr-only">of {r.name}</span>
                      </Button>
                      {run && (
                        <Button
                          variant="ghost"
                          busy={busy === `verify-${r.id}`}
                          onClick={() =>
                            act(`verify-${r.id}`, async () => {
                              const j = await api.post<{ job_id: number }>(`/backup/repositories/${r.id}/verify`);
                              return { kind: "success", text: `Checking every snapshot in ${r.name} (job ${j.job_id}).` };
                            })
                          }
                        >
                          Check now <span className="sr-only">{r.name}</span>
                        </Button>
                      )}
                      {manage && (
                        <Button
                          variant="ghost-danger"
                          onClick={() =>
                            act(`del-${r.id}`, async () => {
                              await api.del(`/backup/repositories/${r.id}`);
                              return { kind: "success", text: `${r.name} was removed from Kernhaven; its data on the target is untouched.` };
                            })
                          }
                        >
                          Remove <span className="sr-only">{r.name}</span>
                        </Button>
                      )}
                    </span>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
        <Card
          title="Plans"
          actions={
            manage &&
            repoList.length > 0 && (
              <Button variant="secondary" onClick={() => setEditPlan("new")}>
                Add a plan
              </Button>
            )
          }
        >
          {plans.data.plans.length === 0 ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">No plans. Nothing is backed up yet.</p>
          ) : (
            <Table
              caption="Backup plans"
              head={
                <tr>
                  <th className={th}>Name</th>
                  <th className={th}>What</th>
                  <th className={th}>Schedule</th>
                  <th className={th}>Last run</th>
                  <th className={th}>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              }
            >
              {plans.data.plans.map((p) => (
                <tr key={p.id}>
                  <td className={td}>
                    {p.name} {!p.enabled && <Badge tone="gray">Disabled</Badge>}
                    <div className="text-xs text-slate-600 dark:text-slate-400">→ {repoList.find((r) => r.id === p.repo)?.name}</div>
                  </td>
                  <td className={td}>{[p.platform ? "platform" : "", p.stacks.join() === "*" ? "all stacks" : p.stacks.join(", ")].filter(Boolean).join(" + ")}</td>
                  <td className={td}>
                    <code className="text-xs">{p.schedule}</code>
                    {p.next && p.enabled && <div className="text-xs text-slate-600 dark:text-slate-400">next {formatDateTime(p.next)}</div>}
                  </td>
                  <td className={td}>
                    {p.last_state ? <JobStateBadge state={p.last_state} /> : <span className="text-slate-600 dark:text-slate-400">never</span>}{" "}
                    {p.last_at && <span className="text-xs text-slate-600 dark:text-slate-400">{formatRelative(p.last_at)}</span>}
                  </td>
                  <td className={td}>
                    <span className="flex gap-1">
                      {run && (
                        <Button
                          variant="ghost"
                          busy={busy === `run-${p.id}`}
                          onClick={() =>
                            act(`run-${p.id}`, async () => {
                              const j = await api.post<{ job_id: number }>(`/backup/plans/${p.id}/run`);
                              return { kind: "success", text: `Backup ${p.name} started (job ${j.job_id}).` };
                            })
                          }
                        >
                          Back up now <span className="sr-only">{p.name}</span>
                        </Button>
                      )}
                      {manage && (
                        <>
                          <Button variant="ghost" onClick={() => setEditPlan(p)}>
                            Edit <span className="sr-only">{p.name}</span>
                          </Button>
                          <Button
                            variant="ghost-danger"
                            onClick={() =>
                              act(`delp-${p.id}`, async () => {
                                await api.del(`/backup/plans/${p.id}`);
                                return { kind: "success", text: `${p.name} was deleted; its snapshots stay.` };
                              })
                            }
                          >
                            Delete <span className="sr-only">{p.name}</span>
                          </Button>
                        </>
                      )}
                    </span>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
        {current && (
          <Card title={`Snapshots — ${current.name}`}>
            <Snapshots key={current.id} repo={current} manage={manage} onNotice={setNotice} />
          </Card>
        )}
        <p className="text-xs text-slate-600 dark:text-slate-400">
          To restore everything on a new host, install Kernhaven and run <code>kernhaven-core restore</code> with the repository&apos;s passphrase before the first start.
        </p>
      </div>
      {addRepo && (
        <RepositoryDialog
          open
          onClose={() => setAddRepo(false)}
          onSaved={(text) => {
            setAddRepo(false);
            setNotice({ kind: "success", text });
            reload();
          }}
        />
      )}
      {editPlan && (
        <PlanDialog
          key={editPlan === "new" ? "new" : editPlan.id}
          plan={editPlan === "new" ? null : editPlan}
          repos={repoList}
          stacks={stacks.data?.stacks ?? []}
          open
          onClose={() => setEditPlan(null)}
          onSaved={(text) => {
            setEditPlan(null);
            setNotice({ kind: "success", text });
            reload();
          }}
        />
      )}
    </>
  );
}
