import { useState } from "react";
import { Alert, Badge, Button, Card, Dialog, DotBadge, PageHeader, SelectField, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatBytes } from "../lib/format";
import { Link } from "../lib/router";
import { useSession } from "../lib/session";
import type { DiskInfo, FileSystemInfo, StorageInventory } from "../lib/types";
import { useData } from "../lib/useData";

const classLabel = { system: "System disk", in_use: "In use", managed: "Kernhaven mount", free: "Free" } as const;
const classTone = { system: "blue", in_use: "amber", managed: "green", free: "gray" } as const;

function Usage({ fs }: { fs: FileSystemInfo }) {
  if (!fs.fs_size_bytes) return <span className="text-slate-600 dark:text-slate-400">—</span>;
  const pct = Math.min(100, Math.round((fs.fs_used_bytes / fs.fs_size_bytes) * 100));
  return (
    <div className="min-w-32">
      <div className="text-xs">
        {formatBytes(fs.fs_used_bytes)} of {formatBytes(fs.fs_size_bytes)} used ({pct}%)
      </div>
      <div className="mt-1 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700" aria-hidden="true">
        <div className={`h-1.5 rounded-full ${pct >= 90 ? "bg-red-600" : pct >= 75 ? "bg-amber-500" : "bg-brand-700"}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function Smart({ disk }: { disk: DiskInfo }) {
  const s = disk.smart;
  if (!s.available) return <span className="text-sm text-slate-600 dark:text-slate-400">SMART unavailable: {s.message}</span>;
  return (
    <span className="flex flex-wrap items-center gap-2 text-sm">
      <Badge tone={s.passed ? "green" : "red"}>SMART {s.passed ? "passed" : "FAILED"}</Badge>
      {s.temperature_c ? <span>{s.temperature_c} °C</span> : null}
      {s.power_on_hours ? <span>{s.power_on_hours.toLocaleString()} hours on</span> : null}
      {s.message && <span className="text-red-700 dark:text-red-400">{s.message}</span>}
    </span>
  );
}

/** StoragePage shows disks, file systems and mounts (AT-F06-01..03). */
export function StoragePage() {
  const { can } = useSession();
  const manage = can("storage.manage");
  const { data, error, loading, reload } = useData(() => api.get<StorageInventory>("/storage"), []);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string; job?: number } | null>(null);
  const [format, setFormat] = useState<DiskInfo | null>(null);
  const [mount, setMount] = useState<FileSystemInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ fstype: "ext4", label: "data", confirm: "", name: "" });
  const [dialogError, setDialogError] = useState<string | null>(null);

  const unmount = async (name: string) => {
    setNotice(null);
    try {
      await api.del(`/storage/mounts/${encodeURIComponent(name)}`);
      setNotice({ kind: "success", text: `${name} was unmounted and will no longer be mounted at boot.` });
    } catch (err) {
      setNotice({ kind: "error", text: errorMessage(err) });
    }
    await reload();
  };
  const submit = async (f: () => Promise<void>) => {
    setBusy(true);
    setDialogError(null);
    try {
      await f();
      await reload();
    } catch (err) {
      setDialogError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const unavailable = error && !data;
  return (
    <>
      <PageHeader title="Storage" description={data ? `Disks, file systems and data disk mounts below ${data.mount_root}.` : "Disks, file systems and data disk mounts."} />
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
      {loading && !data && <Spinner />}
      {unavailable && <Alert>{error}</Alert>}
      {data && !data.privileged && (
        <div className="mb-4">
          <Alert kind="info">The storage service does not run as root here, so disks can be viewed but not formatted or mounted.</Alert>
        </div>
      )}
      {data && (
        <div className="space-y-4">
          {data.disks.map((d) => (
            <Card
              key={d.path}
              title={`${d.name} · ${formatBytes(d.size_bytes)}`}
              actions={
                manage && d.formattable && data.privileged ? (
                  <Button
                    variant="danger"
                    onClick={() => {
                      setForm({ ...form, fstype: data.formattable_fstypes.includes("ext4") ? "ext4" : (data.formattable_fstypes[0] ?? ""), confirm: "" });
                      setDialogError(null);
                      setFormat(d);
                    }}
                  >
                    Format…
                  </Button>
                ) : undefined
              }
            >
              <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
                <Badge tone={classTone[d.class]}>{classLabel[d.class]}</Badge>
                <span>{d.model || "unknown model"}</span>
                {d.serial && <span className="font-mono text-xs text-slate-600 dark:text-slate-400">S/N {d.serial}</span>}
                {d.transport && <Badge>{d.transport}</Badge>}
                {d.removable && <Badge>Removable</Badge>}
                <span className="text-slate-600 dark:text-slate-400">{d.rotational ? "HDD" : "SSD"}</span>
              </div>
              {d.reason && d.class !== "free" && <p className="mb-2 text-sm text-slate-700 dark:text-slate-300">{d.reason}.</p>}
              <div className="mb-3">
                <Smart disk={d} />
              </div>
              {d.file_systems.length === 0 ? (
                <p className="text-sm text-slate-600 dark:text-slate-400">No partitions or file systems.</p>
              ) : (
                <Table
                  caption={`File systems on ${d.name}`}
                  head={
                    <tr>
                      <th className={th}>Device</th>
                      <th className={th}>File system</th>
                      <th className={th}>Size</th>
                      <th className={th}>Usage</th>
                      <th className={th}>Mounted at</th>
                      {manage && (
                        <th className={th}>
                          <span className="sr-only">Actions</span>
                        </th>
                      )}
                    </tr>
                  }
                >
                  {d.file_systems.map((fs) => (
                    <tr key={fs.path}>
                      <td className={td}>{fs.name}</td>
                      <td className={td}>
                        {fs.fstype || "—"}
                        {fs.label && <span className="ml-1 text-slate-600 dark:text-slate-400">“{fs.label}”</span>}
                      </td>
                      <td className={td}>{formatBytes(fs.size_bytes)}</td>
                      <td className={td}>
                        <Usage fs={fs} />
                      </td>
                      <td className={td}>{fs.mountpoints.join(", ") || "—"}</td>
                      {manage && (
                        <td className={td}>
                          {fs.mount_name && data.privileged && (
                            <Button variant="secondary" onClick={() => unmount(fs.mount_name!)}>
                              Unmount <span className="sr-only">{fs.name}</span>
                            </Button>
                          )}
                          {fs.mountable && data.privileged && (
                            <Button
                              variant="secondary"
                              onClick={() => {
                                setForm({ ...form, name: (fs.label || fs.name).toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 31) });
                                setDialogError(null);
                                setMount(fs);
                              }}
                            >
                              Mount <span className="sr-only">{fs.name}</span>
                            </Button>
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </Table>
              )}
            </Card>
          ))}
          <Card title="Kernhaven mounts">
            {data.mounts.length === 0 ? (
              <p className="text-sm text-slate-600 dark:text-slate-400">No data disks are mounted by Kernhaven.</p>
            ) : (
              <ul className="space-y-2 text-sm">
                {data.mounts.map((m) => (
                  <li key={m.name} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono">{m.path}</span>
                    <DotBadge tone={m.active ? "green" : "red"}>{m.active ? "Mounted" : "Not mounted"}</DotBadge>
                    <span className="text-slate-600 dark:text-slate-400">
                      {m.fstype} · {m.unit}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-3 text-xs text-slate-600 dark:text-slate-400">
              Mounts are systemd units (nofail, nosuid, nodev) and come back after a reboot. To use a disk in apps, add {data.mount_root} to the allowed bind roots.
            </p>
          </Card>
        </div>
      )}

      <Dialog open={format !== null} title={`Format ${format?.name ?? ""}?`} onClose={() => setFormat(null)}>
        {format && (
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              void submit(async () => {
                const res = await api.post<{ job_id: number }>("/storage/format", {
                  path: format.path,
                  serial: format.serial,
                  wwn: format.wwn,
                  size_bytes: format.size_bytes,
                  fstype: form.fstype,
                  label: form.label,
                  confirm: form.confirm,
                });
                setFormat(null);
                setNotice({ kind: "success", text: `Formatting ${format.name}.`, job: res.job_id });
              });
            }}
          >
            {dialogError && <Alert>{dialogError}</Alert>}
            <Alert kind="warning">
              Everything on {format.name} ({format.model || "unknown model"}, {formatBytes(format.size_bytes)}
              {format.serial ? `, S/N ${format.serial}` : ""}) will be erased. This cannot be undone.
            </Alert>
            <SelectField label="File system" value={form.fstype} onChange={(e) => setForm({ ...form, fstype: e.target.value })}>
              {data?.formattable_fstypes.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </SelectField>
            <TextField label="Label" hint="1-12 letters, digits, _ or -" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} />
            <TextField label={`Type "${format.name}" to confirm`} autoCapitalize="none" spellCheck={false} value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} />
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setFormat(null)}>
                Cancel
              </Button>
              <Button type="submit" variant="danger" busy={busy} disabled={form.confirm !== format.name || !form.fstype}>
                Erase and format
              </Button>
            </div>
          </form>
        )}
      </Dialog>

      <Dialog open={mount !== null} title={`Mount ${mount?.name ?? ""}`} onClose={() => setMount(null)}>
        {mount && (
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              void submit(async () => {
                await api.post("/storage/mounts", { path: mount.path, uuid: mount.uuid, name: form.name });
                setMount(null);
                setNotice({ kind: "success", text: `${mount.name} is mounted at ${data?.mount_root}/${form.name} and will be mounted at every boot.` });
              });
            }}
          >
            {dialogError && <Alert>{dialogError}</Alert>}
            <TextField label="Folder name" hint={`Mounted at ${data?.mount_root}/${form.name || "…"}. Lowercase letters, digits and -.`} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setMount(null)}>
                Cancel
              </Button>
              <Button type="submit" busy={busy} disabled={form.name === ""}>
                Mount
              </Button>
            </div>
          </form>
        )}
      </Dialog>
    </>
  );
}
