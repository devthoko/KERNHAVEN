import { useState, type ChangeEvent } from "react";
import { Icon } from "../components/Icon";
import { changedValues, DisclosureView, FieldInput, initialValues } from "../components/AppBits";
import { Alert, AppIcon, BackLink, Badge, Button, Card, Dialog, EmptyState, PageHeader, Spinner, StatusBadge, TextField, buttonClass, link } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import type { CatalogAppDetail, CatalogListing, CatalogSource, InstalledApp } from "../lib/types";
import { useData } from "../lib/useData";


export function webURL(port: number): string {
  return `${window.location.protocol}//${window.location.hostname}:${port}/`;
}

/** AppsPage lists the installed apps. */
export function AppsPage() {
  const { can } = useSession();
  const { navigate } = useRouter();
  const { data, error, loading } = useData(() => api.get<{ apps: InstalledApp[] }>("/apps"), [], { refreshMs: 3000, live: ["containers", "jobs"] });
  return (
    <>
      <PageHeader
        title="Apps"
        description="Applications installed from signed catalogs. Updates keep a snapshot of the data and roll back on failure."
        actions={can("apps.manage") && <Button onClick={() => navigate("/apps/store")}>Add an app</Button>}
      />
      {loading && !data && <Spinner />}
      {error && <Alert>{error}</Alert>}
      {data && data.apps.length === 0 && (
        <EmptyState title="No apps installed yet." action={<Button onClick={() => navigate("/apps/store")}>Browse the app store</Button>}>
          Apps come from catalogs whose signatures Kernhaven verified. Before you install one, you see which ports, folders and permissions it asks for.
        </EmptyState>
      )}
      {data && data.apps.length > 0 && (
        <ul className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3" aria-label="Installed apps">
          {data.apps.map((a) => (
            <li key={a.name} className="flex flex-col rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-slate-900">
              <div className="flex items-start gap-3">
                <AppIcon name={a.name} />
                <div className="min-w-0 flex-1">
                  <h2 className="truncate text-base font-semibold">
                    <Link to={`/apps/${a.name}`} className="hover:underline">
                      {a.name}
                    </Link>
                  </h2>
                  <p className="truncate text-sm text-slate-600 dark:text-slate-400">
                    {a.app_name} {a.version && `· ${a.version}`}
                  </p>
                </div>
                <StatusBadge status={a.status} />
              </div>
              {a.update_available && (
                <p className="mt-3">
                  <Badge tone="blue">Update {a.latest_version}</Badge>
                </p>
              )}
              <div className="mt-4 flex flex-wrap gap-2 border-t border-slate-100 pt-3 dark:border-white/5">
                {(a.url || a.web_port > 0) && a.status === "deployed" && (
                  <a
                    href={a.url || webURL(a.web_port)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={buttonClass("primary")}
                  >
                    <Icon name="external" className="size-4" />
                    Open <span className="sr-only">{a.name}</span>
                  </a>
                )}
                <Link
                  to={`/apps/${a.name}`}
                  className={buttonClass("secondary")}
                >
                  Manage <span className="sr-only">{a.name}</span>
                </Link>
              </div>
            </li>
          ))}
        </ul>
      )}
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
      <PageHeader
        title="App store"
        description="Kernhaven Essentials come with Kernhaven. More apps come from catalog sources you add; Kernhaven verifies their signatures."
      />
      <div className="mb-6 space-y-3">
        <div className="max-w-md">
          <TextField label="Search apps" type="search" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
        {data && data.categories.length > 0 && (
          <div role="group" aria-label="Categories" className="flex flex-wrap gap-2">
            {["", ...data.categories].map((c) => (
              <button
                key={c || "all"}
                type="button"
                aria-pressed={c === category}
                onClick={() => setCategory(c)}
                className={`min-h-9 rounded-full px-4 text-sm font-medium ring-1 ring-inset ${
                  c === category
                    ? "bg-slate-900 text-white ring-slate-900 dark:bg-white dark:text-slate-900 dark:ring-white"
                    : "bg-white text-slate-700 ring-slate-300 hover:bg-slate-50 dark:bg-white/5 dark:text-slate-200 dark:ring-white/15 dark:hover:bg-white/10"
                }`}
              >
                {c || "All"}
              </button>
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
              <Card className="relative h-full transition hover:shadow-md motion-reduce:transition-none">
                <div className="flex items-start gap-3">
                  <AppIcon name={a.name} />
                  <div className="min-w-0">
                    <h2 className="text-base font-semibold">
                      {/* The whole card is the link target; the pseudo-element stretches it. */}
                      <Link to={`/apps/store/${a.source_id}/${a.app_id}`} className="after:absolute after:inset-0 after:rounded-xl hover:underline">
                        {a.name}
                      </Link>
                    </h2>
                    <p className="mt-1 line-clamp-2 text-sm text-slate-600 dark:text-slate-400">{a.summary}</p>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
                  <span>v{a.version}</span>
                  <span aria-hidden="true">·</span>
                  {a.builtin ? <Badge tone="blue">Essentials</Badge> : <span>{a.source_name}</span>}
                  {a.categories.map((c) => (
                    <Badge key={c}>{c}</Badge>
                  ))}
                  {a.installed.length > 0 && <Badge tone="green">Installed</Badge>}
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
      <BackLink to="/apps/store">App store</BackLink>
      <PageHeader title={a.name} description={`${a.summary} · version ${a.version} · from ${data.source.name}`} />
      {data.source.builtin && (
        <div className="mb-4">
          <Alert kind="info">Part of Kernhaven Essentials: tested with this Kernhaven version, image pinned by digest, no policy exceptions.</Alert>
        </div>
      )}
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
          <p className="text-sm text-slate-600 dark:text-slate-400">No sources yet. Add the sources you trust.</p>
        </Card>
      )}
      <div className="space-y-4">
        {data?.sources.map((s) => {
          const toggle = manage && (
            <Button
              variant="secondary"
              busy={busy === `toggle-${s.id}`}
              onClick={() =>
                run(`toggle-${s.id}`, () => api.put(`/catalog/sources/${s.id}/enabled`, { enabled: s.disabled }), s.disabled ? `${s.name} is on again.` : `${s.name} is off. Installed apps keep running.`)
              }
            >
              {s.disabled ? "Turn on" : "Turn off"} <span className="sr-only">{s.name}</span>
            </Button>
          );
          const status = (
            <p className="mb-3 flex flex-wrap gap-2">
              {s.builtin && <Badge tone="blue">Comes with Kernhaven</Badge>}
              {s.disabled && <Badge tone="amber">Off: offers no apps and no updates</Badge>}
            </p>
          );
          if (s.builtin) {
            return (
              <Card key={s.id} title={s.name} actions={toggle || undefined}>
                {status}
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  {s.app_count} hand-picked apps, tested with this version of Kernhaven. Images are pinned by digest and no app needs a policy exception. The list is updated with
                  Kernhaven itself, so there is nothing to sync and no key to trust.
                </p>
              </Card>
            );
          }
          return (
            <Card
              key={s.id}
              title={s.name}
              actions={
                manage ? (
                  <div className="flex flex-wrap gap-2">
                    {toggle}
                    {s.url && (
                      <Button variant="secondary" busy={busy === `sync-${s.id}`} onClick={() => run(`sync-${s.id}`, () => api.post(`/catalog/sources/${s.id}/sync`), `${s.name} synced.`)}>
                        Sync
                      </Button>
                    )}
                    <label className={buttonClass("secondary", "cursor-pointer has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-brand-600")}>
                      Upload catalog
                      <input type="file" accept=".json,application/json" className="sr-only" onChange={uploadFile(s)} />
                    </label>
                    <Button variant="ghost-danger" onClick={() => setRemove(s)}>
                      Remove
                    </Button>
                  </div>
                ) : undefined
              }
            >
              {s.disabled && status}
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
          );
        })}
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
