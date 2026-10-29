import { useState, type ChangeEvent } from "react";
import { appStatusTone, changedValues, DisclosureView, FieldInput, initialValues } from "../components/AppBits";
import { Alert, Badge, Button, Card, Dialog, PageHeader, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import type { CatalogAppDetail, CatalogListing, CatalogSource, InstalledApp } from "../lib/types";
import { useData } from "../lib/useData";

const link = "font-medium text-brand-700 underline dark:text-brand-500";

export function webURL(port: number): string {
  return `${window.location.protocol}//${window.location.hostname}:${port}/`;
}

/** AppsPage lists the installed apps. */
export function AppsPage() {
  const { navigate } = useRouter();
  const { data, error, loading } = useData(() => api.get<{ apps: InstalledApp[] }>("/apps"), [], { refreshMs: 3000, live: ["containers", "jobs"] });
  return (
    <>
      <PageHeader
        title="Apps"
        description="Applications installed from signed catalogs. Updates keep a snapshot of the data and roll back on failure."
        actions={<Button onClick={() => navigate("/apps/store")}>App store</Button>}
      />
      <Card>
        {loading && !data && <Spinner />}
        {error && <Alert>{error}</Alert>}
        {data && data.apps.length === 0 && (
          <p className="text-sm text-slate-600 dark:text-slate-400">
            No apps installed yet. <Link to="/apps/store" className={link}>Browse the app store</Link>.
          </p>
        )}
        {data && data.apps.length > 0 && (
          <Table
            caption="Installed apps"
            head={
              <tr>
                <th className={th}>Name</th>
                <th className={th}>App</th>
                <th className={th}>Status</th>
                <th className={th}>Version</th>
                <th className={th}>Open</th>
              </tr>
            }
          >
            {data.apps.map((a) => (
              <tr key={a.name}>
                <td className={td}>
                  <Link to={`/apps/${a.name}`} className={link}>
                    {a.name}
                  </Link>
                </td>
                <td className={td}>{a.app_name}</td>
                <td className={td}>
                  <Badge tone={appStatusTone[a.status]}>{a.status}</Badge>
                </td>
                <td className={td}>
                  {a.version || "—"} {a.update_available && <Badge tone="blue">update {a.latest_version}</Badge>}
                </td>
                <td className={td}>
                  {(a.url || a.web_port > 0) && a.status === "deployed" ? (
                    <a href={a.url || webURL(a.web_port)} target="_blank" rel="noopener noreferrer" className={link}>
                      Open <span className="sr-only">{a.name}</span>
                    </a>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </>
  );
}

/** AppStorePage browses the catalogs (AT-F04-02). */
export function AppStorePage() {
  const { can } = useSession();
  const { navigate, search } = useRouter();
  const [query, setQuery] = useState(search.get("q") ?? "");
  const category = search.get("category") ?? "";
  const params = new URLSearchParams();
  if (query.trim()) params.set("q", query.trim());
  if (category) params.set("category", category);
  const { data, error, loading } = useData(() => api.get<{ apps: CatalogListing[]; categories: string[] }>(`/catalog/apps?${params.toString()}`), [query, category]);
  const setCategory = (c: string) => {
    const p = new URLSearchParams(search);
    if (c) p.set("category", c);
    else p.delete("category");
    navigate(`/apps/store${p.toString() ? `?${p.toString()}` : ""}`, { replace: true });
  };
  return (
    <>
      <p className="mb-2 text-sm">
        <Link to="/apps" className="text-brand-700 underline dark:text-brand-500">
          ← Installed apps
        </Link>
      </p>
      <PageHeader
        title="App store"
        description="Apps from catalogs whose signatures Kernhaven verified."
        actions={
          <Button variant="secondary" onClick={() => navigate("/apps/sources")}>
            {can("catalog.manage") ? "Manage sources" : "Sources"}
          </Button>
        }
      />
      <div className="mb-4 space-y-3">
        <TextField label="Search apps" type="search" value={query} onChange={(e) => setQuery(e.target.value)} />
        {data && data.categories.length > 0 && (
          <div role="group" aria-label="Categories" className="flex flex-wrap gap-2">
            {["", ...data.categories].map((c) => (
              <Button key={c || "all"} variant={c === category ? "primary" : "secondary"} aria-pressed={c === category} onClick={() => setCategory(c)}>
                {c || "All"}
              </Button>
            ))}
          </div>
        )}
      </div>
      {loading && !data && <Spinner />}
      {error && <Alert>{error}</Alert>}
      {data && data.apps.length === 0 && (
        <Card>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            No apps found. {can("catalog.manage") ? <Link to="/apps/sources" className={link}>Add a catalog source</Link> : "Ask an owner to add a catalog source."}
          </p>
        </Card>
      )}
      {data && data.apps.length > 0 && (
        <ul className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {data.apps.map((a) => (
            <li key={`${a.source_id}/${a.app_id}`}>
              <Card className="h-full">
                <h2 className="text-base font-semibold">
                  <Link to={`/apps/store/${a.source_id}/${a.app_id}`} className={link}>
                    {a.name}
                  </Link>
                </h2>
                <p className="mt-1 text-sm text-slate-700 dark:text-slate-300">{a.summary}</p>
                <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
                  <span>v{a.version}</span>
                  <span aria-hidden="true">·</span>
                  <span>{a.source_name}</span>
                  {a.categories.map((c) => (
                    <Badge key={c}>{c}</Badge>
                  ))}
                  {a.installed.length > 0 && <Badge tone="green">installed</Badge>}
                </div>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

/** StoreAppPage shows an app with its disclosure and install form (AT-F04-04, AT-F05-01). */
export function StoreAppPage({ source, app }: { source: string; app: string }) {
  const { can } = useSession();
  const { navigate } = useRouter();
  const { data, error, loading } = useData(() => api.get<CatalogAppDetail>(`/catalog/apps/${encodeURIComponent(source)}/${encodeURIComponent(app)}`), [source, app]);
  const [values, setValues] = useState<Record<string, string> | null>(null);
  const [name, setName] = useState("");
  const [approve, setApprove] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [route, setRoute] = useState({ host: "", path_prefix: "", lan_only: true, sso: false });

  if (loading && !data) return <Spinner />;
  if (!data) return <Alert>{error ?? "App not found."}</Alert>;
  const a = data.app;
  const vals = values ?? initialValues(a.fields);
  const d = data.disclosure;
  const canInstall = can("apps.manage") && d.installable && !data.expired && (!d.needs_approval || (can("policy.exceptions") && approve));

  const install = async () => {
    setBusy(true);
    setFailure(null);
    try {
      const res = await api.post<{ app: InstalledApp; job_id: number; route_error?: string }>("/apps", {
        source_id: data.source.id,
        app_id: a.id,
        name: name.trim() || a.id,
        values: changedValues(vals),
        approve_exceptions: approve,
        ...(route.host.trim() ? { route: { ...route, host: route.host.trim(), path_prefix: route.path_prefix.trim() } } : {}),
      });
      const q = new URLSearchParams({ job: String(res.job_id), ...(res.route_error ? { route_error: res.route_error } : {}) });
      navigate(`/apps/${res.app.name}?${q.toString()}`);
    } catch (err) {
      setFailure(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <>
      <p className="mb-2 text-sm">
        <Link to="/apps/store" className="text-brand-700 underline dark:text-brand-500">
          ← App store
        </Link>
      </p>
      <PageHeader title={a.name} description={`${a.summary} · version ${a.version} · from ${data.source.name}`} />
      {data.expired && (
        <div className="mb-4">
          <Alert kind="warning">The catalog of {data.source.name} has expired. An owner must sync it before apps can be installed.</Alert>
        </div>
      )}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="About">
          {a.description ? <p className="whitespace-pre-line text-sm">{a.description}</p> : <p className="text-sm">{a.summary}</p>}
          {a.homepage && (
            <p className="mt-3 text-sm">
              <a href={a.homepage} target="_blank" rel="noopener noreferrer" className={link}>
                Project homepage
              </a>
            </p>
          )}
          {data.installed.length > 0 && <p className="mt-3 text-sm">Installed as: {data.installed.join(", ")}</p>}
        </Card>
        <Card title="What this app can do">
          <DisclosureView disclosure={d} />
        </Card>
        {can("apps.manage") && d.installable && (
          <Card title="Install" className="lg:col-span-2">
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                void install();
              }}
            >
              {failure && <Alert>{failure}</Alert>}
              <TextField label="Name" hint={`Lowercase letters, digits and -. Default: ${a.id}`} value={name} placeholder={a.id} onChange={(e) => setName(e.target.value)} />
              <div className="grid gap-4 sm:grid-cols-2">
                {a.fields.map((f) => (
                  <FieldInput key={f.name} field={f} value={vals[f.name] ?? ""} onChange={(v) => setValues({ ...vals, [f.name]: v })} />
                ))}
              </div>
              {a.web && can("network.manage") && (
                <fieldset className="space-y-3">
                  <legend className="text-sm font-medium">Web address (optional)</legend>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <TextField
                      label="Host name"
                      hint="Publishes the app through Kernhaven's reverse proxy, for example notes.home.arpa"
                      autoCapitalize="none"
                      spellCheck={false}
                      value={route.host}
                      onChange={(e) => setRoute({ ...route, host: e.target.value })}
                    />
                    <TextField label="Path prefix (optional)" autoCapitalize="none" spellCheck={false} value={route.path_prefix} onChange={(e) => setRoute({ ...route, path_prefix: e.target.value })} />
                  </div>
                  {route.host.trim() && (
                    <div className="space-y-2 text-sm">
                      <label className="flex items-start gap-2">
                        <input type="checkbox" className="mt-1 size-4" checked={route.lan_only} onChange={(e) => setRoute({ ...route, lan_only: e.target.checked })} />
                        <span>Only from the local network</span>
                      </label>
                      <label className="flex items-start gap-2">
                        <input type="checkbox" className="mt-1 size-4" checked={route.sso} onChange={(e) => setRoute({ ...route, sso: e.target.checked })} />
                        <span>Require Kernhaven sign-in</span>
                      </label>
                    </div>
                  )}
                </fieldset>
              )}
              {d.needs_approval &&
                (can("policy.exceptions") ? (
                  <label className="flex items-start gap-2 text-sm">
                    <input type="checkbox" className="mt-1 size-4" checked={approve} onChange={(e) => setApprove(e.target.checked)} />
                    <span>I approve the policy exceptions listed above for this app.</span>
                  </label>
                ) : (
                  <Alert kind="warning">Only an owner can install this app.</Alert>
                ))}
              <Button type="submit" busy={busy} disabled={!canInstall}>
                Install
              </Button>
            </form>
          </Card>
        )}
      </div>
    </>
  );
}

/** SourcesPage manages catalog sources (AT-F04-03). */
export function SourcesPage() {
  const { can } = useSession();
  const manage = can("catalog.manage");
  const { data, error, loading, reload } = useData(() => api.get<{ sources: CatalogSource[] }>("/catalog/sources"), []);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ name: "", url: "", public_key: "" });
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [remove, setRemove] = useState<CatalogSource | null>(null);

  const run = async (key: string, f: () => Promise<unknown>, success: string) => {
    setBusy(key);
    setNotice(null);
    try {
      await f();
      setNotice({ kind: "success", text: success });
      await reload();
    } catch (err) {
      setNotice({ kind: "error", text: errorMessage(err) });
      await reload();
    } finally {
      setBusy(null);
    }
  };
  const uploadFile = (src: CatalogSource) => async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    await run(
      `upload-${src.id}`,
      async () => {
        let body: unknown;
        try {
          body = JSON.parse(await file.text());
        } catch {
          throw new Error("The file is not a signed catalog (invalid JSON).");
        }
        await api.post(`/catalog/sources/${src.id}/upload`, body);
      },
      `Catalog for ${src.name} verified and accepted.`,
    );
  };

  return (
    <>
      <p className="mb-2 text-sm">
        <Link to="/apps/store" className="text-brand-700 underline dark:text-brand-500">
          ← App store
        </Link>
      </p>
      <PageHeader
        title="Catalog sources"
        description="Each source has its own signing key. Catalogs whose signature does not match are rejected."
        actions={manage ? <Button onClick={() => setAdding(true)}>Add source</Button> : undefined}
      />
      {notice && (
        <div className="mb-4">
          <Alert kind={notice.kind}>{notice.text}</Alert>
        </div>
      )}
      {loading && !data && <Spinner />}
      {error && <Alert>{error}</Alert>}
      {data && data.sources.length === 0 && (
        <Card>
          <p className="text-sm text-slate-600 dark:text-slate-400">No sources yet. Kernhaven ships without a default catalog; add the sources you trust.</p>
        </Card>
      )}
      <div className="space-y-4">
        {data?.sources.map((s) => (
          <Card
            key={s.id}
            title={s.name}
            actions={
              manage ? (
                <div className="flex flex-wrap gap-2">
                  {s.url && (
                    <Button variant="secondary" busy={busy === `sync-${s.id}`} onClick={() => run(`sync-${s.id}`, () => api.post(`/catalog/sources/${s.id}/sync`), `${s.name} synced.`)}>
                      Sync
                    </Button>
                  )}
                  <label className="inline-flex min-h-10 cursor-pointer items-center rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-800 hover:bg-slate-100 has-[:focus-visible]:outline-2 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100">
                    Upload catalog
                    <input type="file" accept=".json,application/json" className="sr-only" onChange={uploadFile(s)} />
                  </label>
                  <Button variant="ghost" className="text-red-700 dark:text-red-400" onClick={() => setRemove(s)}>
                    Remove
                  </Button>
                </div>
              ) : undefined
            }
          >
            <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
              <dt className="text-slate-600 dark:text-slate-400">URL</dt>
              <dd className="break-all">{s.url || "upload only"}</dd>
              <dt className="text-slate-600 dark:text-slate-400">Key ID</dt>
              <dd className="font-mono">{s.key_id}</dd>
              <dt className="text-slate-600 dark:text-slate-400">Catalog</dt>
              <dd>{s.serial > 0 ? `${s.catalog_name} · serial ${s.serial} · ${s.app_count} apps` : "not synced yet"}</dd>
              <dt className="text-slate-600 dark:text-slate-400">Synced</dt>
              <dd>{s.synced_at ? formatDateTime(s.synced_at) : "—"}</dd>
              <dt className="text-slate-600 dark:text-slate-400">Expires</dt>
              <dd>{s.expires_at ? formatDateTime(s.expires_at) : "—"}</dd>
            </dl>
            {s.last_error && (
              <div className="mt-3">
                <Alert>Last catalog rejected: {s.last_error}</Alert>
              </div>
            )}
          </Card>
        ))}
      </div>
      <Dialog open={adding} title="Add catalog source" onClose={() => setAdding(false)}>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void run(
              "add",
              async () => {
                await api.post("/catalog/sources", form);
                setAdding(false);
                setForm({ name: "", url: "", public_key: "" });
              },
              "Source added. Sync it or upload its signed catalog.",
            );
          }}
        >
          <TextField label="Name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <TextField label="Catalog URL (optional)" hint="Public https address. Leave empty to upload catalogs." value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} />
          <TextField
            label="Trust key"
            hint="The publisher's Ed25519 public key (base64), from kernhaven-catalog keygen."
            required
            autoCapitalize="none"
            spellCheck={false}
            value={form.public_key}
            onChange={(e) => setForm({ ...form, public_key: e.target.value })}
          />
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setAdding(false)}>
              Cancel
            </Button>
            <Button type="submit" busy={busy === "add"}>
              Add source
            </Button>
          </div>
        </form>
      </Dialog>
      <Dialog open={remove !== null} title={`Remove ${remove?.name ?? ""}?`} onClose={() => setRemove(null)}>
        <p className="mb-4 text-sm">Apps installed from this source keep running but no longer receive updates.</p>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setRemove(null)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            busy={busy === "remove"}
            onClick={() => {
              const s = remove;
              setRemove(null);
              if (s) void run("remove", () => api.del(`/catalog/sources/${s.id}`), `${s.name} removed.`);
            }}
          >
            Remove source
          </Button>
        </div>
      </Dialog>
    </>
  );
}
