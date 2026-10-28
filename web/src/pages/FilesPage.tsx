import { useRef, useState, type ChangeEvent } from "react";
import { Alert, Badge, Button, Card, Dialog, PageHeader, SelectField, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, ApiError, errorMessage, putBinary } from "../lib/api";
import { formatBytes, formatDateTime } from "../lib/format";
import { Link, useRouter } from "../lib/router";
import type { FileEntry, FileListing, FilePreview, FileRootView, TrashItem, UploadSession } from "../lib/types";
import { useData } from "../lib/useData";

const link = "text-brand-700 underline dark:text-brand-500";

function join(dir: string, name: string): string {
  return dir ? `${dir}/${name}` : name;
}

function parent(p: string): string {
  const i = p.lastIndexOf("/");
  return i < 0 ? "" : p.slice(0, i);
}

function query(root: string, path: string): string {
  return `root=${encodeURIComponent(root)}&path=${encodeURIComponent(path)}`;
}

/**
 * upload sends a file in chunks and resumes after interruptions by asking
 * the server how much it received (AT-F07-02).
 */
async function upload(root: string, path: string, file: File, onProgress: (n: number) => void, signal: { cancelled: boolean }) {
  const s = await api.post<UploadSession>("/files/uploads", { root, path, size: file.size });
  let offset = 0;
  let failures = 0;
  while (offset < file.size) {
    if (signal.cancelled) {
      await api.del(`/files/uploads/${s.id}`).catch(() => undefined);
      throw new Error("Upload cancelled.");
    }
    try {
      const res = await putBinary<{ received: number }>(`/files/uploads/${s.id}?offset=${offset}`, file.slice(offset, offset + s.chunk_size));
      offset = res.received;
      failures = 0;
      onProgress(offset);
    } catch (err) {
      if (err instanceof ApiError && err.status >= 400 && err.status < 500 && err.status !== 409) throw err;
      if (++failures > 5) throw err;
      await new Promise((r) => setTimeout(r, 1000 * failures));
      const st = await api.get<UploadSession>(`/files/uploads/${s.id}`);
      offset = st.received;
    }
  }
  await api.post(`/files/uploads/${s.id}/finish`);
}

type DialogState =
  | { kind: "mkdir" }
  | { kind: "rename"; entry: FileEntry }
  | { kind: "copy"; entry: FileEntry }
  | { kind: "delete"; entry: FileEntry }
  | { kind: "preview"; entry: FileEntry; preview?: FilePreview; error?: string }
  | null;

/** FilesPage is the file manager (AT-F07-01..05). */
export function FilesPage() {
  const { search, navigate } = useRouter();
  const roots = useData(() => api.get<{ roots: FileRootView[] }>("/files/roots"), []);
  const rootList = roots.data?.roots ?? [];
  const root = search.get("root") ?? rootList[0]?.name ?? "";
  const dir = search.get("path") ?? "";
  const showTrash = search.get("view") === "trash";
  const current = rootList.find((r) => r.name === root);
  const writable = current?.writable ?? false;
  const listing = useData(() => (root && !showTrash ? api.get<FileListing>(`/files/list?${query(root, dir)}`) : Promise.resolve(null)), [root, dir, showTrash]);
  const trash = useData(() => (root && showTrash ? api.get<{ items: TrashItem[] }>(`/files/trash?root=${encodeURIComponent(root)}`) : Promise.resolve(null)), [root, showTrash]);
  const [dialog, setDialog] = useState<DialogState>(null);
  const [name, setName] = useState("");
  const [target, setTarget] = useState({ root: "", path: "" });
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string; job?: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ name: string; done: number; total: number } | null>(null);
  const cancel = useRef({ cancelled: false });

  const go = (r: string, p: string, view?: string) => {
    const q = new URLSearchParams({ root: r });
    if (p) q.set("path", p);
    if (view) q.set("view", view);
    navigate(`/files?${q.toString()}`);
  };
  const act = async (f: () => Promise<unknown>, success: string, job = false) => {
    setBusy(true);
    setDialogError(null);
    try {
      const res = (await f()) as { job_id?: number } | undefined;
      setDialog(null);
      setNotice({ kind: "success", text: success, job: job ? res?.job_id : undefined });
      await Promise.all([listing.reload(), trash.reload()]);
    } catch (err) {
      setDialogError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const onUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    e.target.value = "";
    cancel.current = { cancelled: false };
    setNotice(null);
    for (const f of files) {
      setProgress({ name: f.name, done: 0, total: f.size });
      try {
        await upload(root, join(dir, f.name), f, (done) => setProgress({ name: f.name, done, total: f.size }), cancel.current);
      } catch (err) {
        setNotice({ kind: "error", text: `${f.name}: ${errorMessage(err)}` });
        break;
      }
    }
    setProgress(null);
    await listing.reload();
  };
  const openPreview = async (entry: FileEntry) => {
    setDialog({ kind: "preview", entry });
    try {
      const pv = await api.get<FilePreview>(`/files/preview?${query(root, join(dir, entry.name))}`);
      setDialog({ kind: "preview", entry, preview: pv });
    } catch (err) {
      setDialog({ kind: "preview", entry, error: errorMessage(err) });
    }
  };

  if (roots.loading && !roots.data) return <Spinner />;
  if (roots.error) return <Alert>{roots.error}</Alert>;
  if (rootList.length === 0) {
    return (
      <>
        <PageHeader title="Files" />
        <Alert kind="info">No file roots are available to you.</Alert>
      </>
    );
  }
  const crumbs = dir ? dir.split("/") : [];

  return (
    <>
      <PageHeader
        title="Files"
        description={current ? `${formatBytes(current.free_bytes)} free of ${formatBytes(current.total_bytes)}` : undefined}
        actions={
          <>
            {rootList.length > 1 && (
              <SelectField label="Root" value={root} onChange={(e) => go(e.target.value, "")}>
                {rootList.map((r) => (
                  <option key={r.name} value={r.name}>
                    {r.name}
                  </option>
                ))}
              </SelectField>
            )}
          </>
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
      {progress && (
        <div className="mb-4">
          <Card>
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <span className="min-w-0 break-all">
                Uploading {progress.name}: {formatBytes(progress.done)} of {formatBytes(progress.total)}
              </span>
              <progress className="h-2 w-40" max={progress.total || 1} value={progress.done} aria-label={`Upload progress of ${progress.name}`} />
              <Button variant="ghost" onClick={() => (cancel.current.cancelled = true)}>
                Cancel
              </Button>
            </div>
          </Card>
        </div>
      )}
      {current && !current.available && <Alert>The root {root} is not available. Is its disk mounted?</Alert>}

      <Card>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <nav aria-label="Folder" className="flex min-w-0 flex-wrap items-center gap-1 text-sm">
            <button type="button" className={link} onClick={() => go(root, "")}>
              {root}
            </button>
            {crumbs.map((c, i) => (
              <span key={i} className="flex items-center gap-1">
                <span aria-hidden="true">/</span>
                <button type="button" className={`${link} break-all`} onClick={() => go(root, crumbs.slice(0, i + 1).join("/"))} aria-current={i === crumbs.length - 1 ? "location" : undefined}>
                  {c}
                </button>
              </span>
            ))}
          </nav>
          <div className="flex flex-wrap gap-2">
            {showTrash ? (
              <Button variant="secondary" onClick={() => go(root, dir)}>
                Back to files
              </Button>
            ) : (
              <>
                {writable && (
                  <>
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setName("");
                        setDialogError(null);
                        setDialog({ kind: "mkdir" });
                      }}
                    >
                      New folder
                    </Button>
                    <label className="inline-flex min-h-10 cursor-pointer items-center rounded-md bg-brand-700 px-4 py-2 text-sm font-medium text-white hover:bg-brand-800 has-[:focus-visible]:outline-2">
                      Upload
                      <input type="file" multiple className="sr-only" disabled={progress !== null} onChange={onUpload} />
                    </label>
                  </>
                )}
                <Button variant="ghost" onClick={() => go(root, dir, "trash")}>
                  Trash
                </Button>
              </>
            )}
          </div>
        </div>

        {showTrash ? (
          <>
            {trash.loading && !trash.data && <Spinner />}
            {trash.error && <Alert>{trash.error}</Alert>}
            {trash.data && trash.data.items.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">The trash is empty.</p>}
            {trash.data && trash.data.items.length > 0 && (
              <>
                <Table
                  caption="Trash"
                  head={
                    <tr>
                      <th className={th}>Original location</th>
                      <th className={th}>Deleted</th>
                      <th className={th}>By</th>
                      {writable && (
                        <th className={th}>
                          <span className="sr-only">Actions</span>
                        </th>
                      )}
                    </tr>
                  }
                >
                  {trash.data.items.map((t) => (
                    <tr key={t.id}>
                      <td className={`${td} max-w-xs truncate`}>
                        {t.path}
                        {t.is_dir ? "/" : ""}
                      </td>
                      <td className={td}>{formatDateTime(t.deleted_at)}</td>
                      <td className={td}>{t.deleted_by}</td>
                      {writable && (
                        <td className={td}>
                          <Button variant="secondary" disabled={busy} onClick={() => act(() => api.post("/files/trash/restore", { root, id: t.id }), `Restored ${t.path}.`)}>
                            Restore <span className="sr-only">{t.path}</span>
                          </Button>
                        </td>
                      )}
                    </tr>
                  ))}
                </Table>
                {writable && (
                  <div className="mt-3">
                    <Button variant="danger" disabled={busy} onClick={() => act(() => api.post("/files/trash/purge", { root }), "Emptying the trash.", true)}>
                      Empty trash
                    </Button>
                  </div>
                )}
              </>
            )}
          </>
        ) : (
          <>
            {listing.loading && !listing.data && <Spinner />}
            {listing.error && <Alert>{listing.error}</Alert>}
            {listing.data && listing.data.entries.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">This folder is empty.</p>}
            {listing.data?.truncated && <Alert kind="warning">Only the first 10 000 entries are shown.</Alert>}
            {listing.data && listing.data.entries.length > 0 && (
              <Table
                caption={`Contents of ${root}/${dir}`}
                head={
                  <tr>
                    <th className={th}>Name</th>
                    <th className={th}>Size</th>
                    <th className={th}>Modified</th>
                    <th className={th}>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                }
              >
                {dir && (
                  <tr>
                    <td className={td} colSpan={4}>
                      <button type="button" className={link} onClick={() => go(root, parent(dir))}>
                        .. (up)
                      </button>
                    </td>
                  </tr>
                )}
                {listing.data.entries.map((e) => {
                  const p = join(dir, e.name);
                  return (
                    <tr key={e.name}>
                      <td className={`${td} max-w-xs`}>
                        <span className="flex min-w-0 items-center gap-2">
                          <span aria-hidden="true">{e.type === "dir" ? "📁" : e.type === "symlink" ? "↪" : "📄"}</span>
                          {e.type === "dir" ? (
                            <button type="button" className={`${link} truncate`} onClick={() => go(root, p)}>
                              {e.name}
                            </button>
                          ) : (
                            <span className="truncate">{e.name}</span>
                          )}
                          {e.type === "symlink" && <Badge>link</Badge>}
                        </span>
                      </td>
                      <td className={td}>{e.type === "dir" ? "—" : formatBytes(e.size)}</td>
                      <td className={td}>{formatDateTime(e.mod_time)}</td>
                      <td className="px-4 py-1">
                        <span className="flex flex-wrap gap-x-1">
                          {e.type === "file" && (
                            <>
                              <Button variant="ghost" className="px-2" onClick={() => openPreview(e)}>
                                View <span className="sr-only">{e.name}</span>
                              </Button>
                              <a className="inline-flex min-h-10 items-center rounded-md px-2 text-sm font-medium text-slate-700 hover:bg-slate-200 dark:text-slate-200 dark:hover:bg-slate-800" href={`/api/v1/files/download?${query(root, p)}`} download>
                                Download <span className="sr-only">{e.name}</span>
                              </a>
                            </>
                          )}
                          {writable && (
                            <>
                              <Button
                                variant="ghost"
                                className="px-2"
                                onClick={() => {
                                  setName(e.name);
                                  setDialogError(null);
                                  setDialog({ kind: "rename", entry: e });
                                }}
                              >
                                Rename <span className="sr-only">{e.name}</span>
                              </Button>
                              <Button
                                variant="ghost"
                                className="px-2"
                                onClick={() => {
                                  setTarget({ root, path: `${p} copy` });
                                  setDialogError(null);
                                  setDialog({ kind: "copy", entry: e });
                                }}
                              >
                                Copy <span className="sr-only">{e.name}</span>
                              </Button>
                              <Button
                                variant="ghost"
                                className="px-2 text-red-700 dark:text-red-400"
                                onClick={() => {
                                  setDialogError(null);
                                  setDialog({ kind: "delete", entry: e });
                                }}
                              >
                                Delete <span className="sr-only">{e.name}</span>
                              </Button>
                            </>
                          )}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </Table>
            )}
          </>
        )}
      </Card>

      <Dialog open={dialog?.kind === "mkdir" || dialog?.kind === "rename"} title={dialog?.kind === "rename" ? `Rename ${dialog.entry.name}` : "New folder"} onClose={() => setDialog(null)}>
        <form
          className="space-y-4"
          onSubmit={(ev) => {
            ev.preventDefault();
            if (dialog?.kind === "rename") {
              void act(() => api.post("/files/rename", { root, from: join(dir, dialog.entry.name), to: join(dir, name) }), `Renamed to ${name}.`);
            } else {
              void act(() => api.post("/files/mkdir", { root, path: join(dir, name) }), `Created ${name}.`);
            }
          }}
        >
          {dialogError && <Alert>{dialogError}</Alert>}
          <TextField label="Name" required value={name} onChange={(e) => setName(e.target.value)} />
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setDialog(null)}>
              Cancel
            </Button>
            <Button type="submit" busy={busy} disabled={!name || name.includes("/")}>
              {dialog?.kind === "rename" ? "Rename" : "Create"}
            </Button>
          </div>
        </form>
      </Dialog>

      <Dialog open={dialog?.kind === "copy"} title={`Copy ${dialog?.kind === "copy" ? dialog.entry.name : ""}`} onClose={() => setDialog(null)}>
        {dialog?.kind === "copy" && (
          <form
            className="space-y-4"
            onSubmit={(ev) => {
              ev.preventDefault();
              void act(() => api.post("/files/copy", { root, from: join(dir, dialog.entry.name), to_root: target.root, to: target.path }), "Copying.", true);
            }}
          >
            {dialogError && <Alert>{dialogError}</Alert>}
            <SelectField label="Target root" value={target.root} onChange={(e) => setTarget({ ...target, root: e.target.value })}>
              {rootList
                .filter((r) => r.writable)
                .map((r) => (
                  <option key={r.name} value={r.name}>
                    {r.name}
                  </option>
                ))}
            </SelectField>
            <TextField label="Target path" hint="Relative to the target root. Existing files are never overwritten." value={target.path} onChange={(e) => setTarget({ ...target, path: e.target.value })} />
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setDialog(null)}>
                Cancel
              </Button>
              <Button type="submit" busy={busy} disabled={!target.path}>
                Copy
              </Button>
            </div>
          </form>
        )}
      </Dialog>

      <Dialog open={dialog?.kind === "delete"} title={`Delete ${dialog?.kind === "delete" ? dialog.entry.name : ""}?`} onClose={() => setDialog(null)}>
        {dialog?.kind === "delete" && (
          <div className="space-y-4">
            {dialogError && <Alert>{dialogError}</Alert>}
            <p className="text-sm">It is moved to the trash of {root} and can be restored from there.</p>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setDialog(null)}>
                Cancel
              </Button>
              <Button variant="danger" busy={busy} onClick={() => act(() => api.post("/files/trash", { root, path: join(dir, dialog.entry.name) }), `${dialog.entry.name} was moved to the trash.`)}>
                Move to trash
              </Button>
            </div>
          </div>
        )}
      </Dialog>

      <Dialog open={dialog?.kind === "preview"} title={dialog?.kind === "preview" ? dialog.entry.name : ""} onClose={() => setDialog(null)}>
        {dialog?.kind === "preview" && (
          <div className="space-y-3">
            {!dialog.preview && !dialog.error && <Spinner />}
            {dialog.error && <Alert>{dialog.error}</Alert>}
            {dialog.preview?.kind === "text" && (
              <>
                <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-100 p-3 text-xs dark:bg-slate-800">{dialog.preview.text}</pre>
                {dialog.preview.truncated && <p className="text-xs text-slate-600 dark:text-slate-400">Only the beginning of the file is shown.</p>}
              </>
            )}
            {dialog.preview?.kind === "image" && (
              <img src={`/api/v1/files/image?${query(root, join(dir, dialog.entry.name))}`} alt={dialog.entry.name} className="max-h-96 max-w-full" />
            )}
            {dialog.preview?.kind === "binary" && <p className="text-sm">This file cannot be previewed. Download it instead.</p>}
            <div className="flex justify-end">
              <Button variant="secondary" onClick={() => setDialog(null)}>
                Close
              </Button>
            </div>
          </div>
        )}
      </Dialog>
    </>
  );
}
