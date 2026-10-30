import { useId, useState } from "react";
import { Alert, Badge, Button, Card, Dialog, DotBadge, PageHeader, SelectField, Spinner, Table, TextField, inputClass, link, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime, roleLabel } from "../lib/format";
import { Link } from "../lib/router";
import { useSession } from "../lib/session";
import type { NetworkOverview, ProxyRoute, ProxyRouteInput, ProxyState, Role } from "../lib/types";
import { useData } from "../lib/useData";

const roles: Role[] = ["viewer", "operator", "admin", "owner"];

function emptyInput(): ProxyRouteInput {
  return { host: "", path_prefix: "", strip_prefix: false, upstream_port: 0, sso: false, sso_min_role: "viewer", lan_only: true, allow_cidrs: [] };
}

function inputOf(r: ProxyRoute): ProxyRouteInput {
  const { host, path_prefix, strip_prefix, upstream_port, sso, sso_min_role, lan_only, allow_cidrs } = r;
  return { host, path_prefix, strip_prefix, upstream_port, sso, sso_min_role, lan_only, allow_cidrs };
}

function Access({ r }: { r: ProxyRoute }) {
  const parts = [];
  if (r.lan_only) parts.push(<Badge key="lan" tone="blue">LAN only</Badge>);
  if (r.allow_cidrs.length > 0) parts.push(<Badge key="ip" tone="blue">{r.allow_cidrs.length === 1 ? r.allow_cidrs[0] : `${r.allow_cidrs.length} networks`}</Badge>);
  if (r.sso) parts.push(<Badge key="sso" tone="green">Kernhaven sign-in ({roleLabel(r.sso_min_role)}+)</Badge>);
  if (parts.length === 0) parts.push(<Badge key="open" tone="amber">Open to everyone who reaches it</Badge>);
  return <span className="flex flex-wrap gap-1">{parts}</span>;
}

function StatusCard({ st, manage, onApplied }: { st: ProxyState; manage: boolean; onApplied: () => void }) {
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  if (!st.configured) {
    return (
      <Card title="Caddy">
        <Alert kind="info">No proxy service is configured (agent.proxy_socket in core.toml). Routes cannot be published.</Alert>
      </Card>
    );
  }
  return (
    <Card
      title="Caddy"
      actions={
        manage && (
          <Button
            variant="secondary"
            busy={busy}
            onClick={async () => {
              setBusy(true);
              setNotice(null);
              try {
                await api.post("/network/apply");
                setNotice({ kind: "success", text: "The routes were applied again." });
                onApplied();
              } catch (err) {
                setNotice({ kind: "error", text: errorMessage(err) });
              } finally {
                setBusy(false);
              }
            }}
          >
            Apply again
          </Button>
        )
      }
    >
      <div className="space-y-3 text-sm">
        {notice && <Alert kind={notice.kind}>{notice.text}</Alert>}
        <p className="flex flex-wrap items-center gap-2">
          {st.reachable ? <DotBadge tone="green">Running</DotBadge> : <DotBadge tone="red">Not reachable</DotBadge>}
          {st.reachable && (st.in_sync ? <Badge tone="green">Configuration in sync</Badge> : <Badge tone="amber">Configuration differs — apply again</Badge>)}
          {st.applied_at && <span>Last applied {formatDateTime(st.applied_at)}</span>}
        </p>
        {st.error && (
          <Alert kind="warning">
            Last change refused{st.error_at ? ` (${formatDateTime(st.error_at)})` : ""}: {st.error}. The previous configuration stayed active.
          </Alert>
        )}
        <p className="text-slate-600 dark:text-slate-400">
          Caddy serves every route with HTTPS on port {st.https_port}. Certificates come from Kernhaven&apos;s own certificate authority unless you choose another source
          under{" "}
          <Link to="/certificates" className={link}>
            Certificates
          </Link>
          .
        </p>
      </div>
    </Card>
  );
}

function RouteDialog({ route, open, onClose, onSaved }: { route: ProxyRoute | null; open: boolean; onClose: () => void; onSaved: (text: string) => void }) {
  const [form, setForm] = useState<ProxyRouteInput>(() => (route ? inputOf(route) : emptyInput()));
  const [cidrs, setCidrs] = useState(() => (route ? route.allow_cidrs.join("\n") : ""));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cidrId = useId();
  const set = (patch: Partial<ProxyRouteInput>) => setForm({ ...form, ...patch });

  const save = async () => {
    setBusy(true);
    setError(null);
    const body = { ...form, allow_cidrs: cidrs.split(/[\s,]+/).filter(Boolean), strip_prefix: form.path_prefix !== "" && form.strip_prefix };
    try {
      if (route) await api.put(`/network/routes/${route.id}`, body);
      else await api.post("/network/routes", body);
      onSaved(route ? `${form.host}${form.path_prefix} was updated.` : `${form.host}${form.path_prefix} is published.`);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} title={route ? `Edit ${route.host}${route.path_prefix}` : "Add a route"} onClose={onClose}>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        {error && <Alert>{error}</Alert>}
        {route?.app && <Alert kind="info">This route belongs to the app {route.app}; an update of the app may change its port.</Alert>}
        <TextField label="Host name" hint="For example jellyfin.home.arpa. Your DNS must point it to this server." required autoCapitalize="none" spellCheck={false} value={form.host} onChange={(e) => set({ host: e.target.value })} />
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField label="Path prefix (optional)" hint="For example /books" autoCapitalize="none" spellCheck={false} value={form.path_prefix} onChange={(e) => set({ path_prefix: e.target.value })} />
          <TextField
            label="Port on this server"
            hint="1024–65535, reached on 127.0.0.1"
            type="number"
            inputMode="numeric"
            min={1024}
            max={65535}
            required
            value={form.upstream_port || ""}
            onChange={(e) => set({ upstream_port: Number(e.target.value) })}
          />
        </div>
        {form.path_prefix !== "" && (
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-1 size-4" checked={form.strip_prefix} onChange={(e) => set({ strip_prefix: e.target.checked })} />
            <span>Remove the prefix before passing requests on (for apps that expect to run at /)</span>
          </label>
        )}
        <fieldset className="space-y-3 text-sm">
          <legend className="mb-1 font-medium">Who may open it</legend>
          <label className="flex items-start gap-2">
            <input type="checkbox" className="mt-1 size-4" checked={form.lan_only} onChange={(e) => set({ lan_only: e.target.checked })} />
            <span>Only from the local network (private addresses)</span>
          </label>
          <label className="flex items-start gap-2">
            <input type="checkbox" className="mt-1 size-4" checked={form.sso} onChange={(e) => set({ sso: e.target.checked })} />
            <span>Require Kernhaven sign-in</span>
          </label>
          {form.sso && (
            <SelectField label="Minimum role" value={form.sso_min_role} onChange={(e) => set({ sso_min_role: e.target.value as Role })}>
              {roles.map((r) => (
                <option key={r} value={r}>
                  {roleLabel(r)}
                </option>
              ))}
            </SelectField>
          )}
          <div className="space-y-1">
            <label htmlFor={cidrId} className="block font-medium">
              Allowed networks (optional)
            </label>
            <textarea
              id={cidrId}
              rows={3}
              aria-describedby={`${cidrId}-hint`}
              className={`${inputClass} font-mono`}
              placeholder={"192.168.1.0/24\n2001:db8::/32"}
              spellCheck={false}
              value={cidrs}
              onChange={(e) => setCidrs(e.target.value)}
            />
            <p id={`${cidrId}-hint`} className="text-xs text-slate-600 dark:text-slate-400">
              One address or range per line. Other clients get 403.
            </p>
          </div>
        </fieldset>
        {!form.lan_only && !form.sso && cidrs.trim() === "" && (
          <Alert kind="warning">Without restrictions anyone who can reach this server can open the app. Its own login is then the only protection.</Alert>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" busy={busy} disabled={!form.host.trim() || !form.upstream_port}>
            {route ? "Save" : "Publish"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function Overview() {
  const { can } = useSession();
  const { data, error, loading } = useData(() => api.get<NetworkOverview>("/network/overview"), []);
  if (loading && !data) return <Spinner />;
  if (!data) return <Alert kind="info">{error ?? "The network overview is not available."}</Alert>;
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card title="Interfaces">
        <Table
          caption="Network interfaces"
          head={
            <tr>
              <th className={th}>Name</th>
              <th className={th}>State</th>
              <th className={th}>Addresses</th>
            </tr>
          }
        >
          {data.interfaces.map((i) => (
            <tr key={i.name}>
              <td className={td}>
                {i.name}
                {i.mac && <div className="font-mono text-xs text-slate-600 dark:text-slate-400">{i.mac}</div>}
              </td>
              <td className={td}>{i.up ? <DotBadge tone="green">Up</DotBadge> : <DotBadge tone="gray">Down</DotBadge>}</td>
              <td className={`${td} font-mono text-xs`}>
                {i.addresses.map((a) => (
                  <div key={a}>{a}</div>
                ))}
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      <Card title="Listening ports">
        <Table
          caption="Listening ports"
          head={
            <tr>
              <th className={th}>Port</th>
              <th className={th}>Protocol</th>
              <th className={th}>Address</th>
            </tr>
          }
        >
          {data.listening.map((l) => (
            <tr key={`${l.protocol}-${l.address}-${l.port}`}>
              <td className={td}>{l.port}</td>
              <td className={td}>{l.protocol}</td>
              <td className={`${td} font-mono text-xs`}>{l.address}</td>
            </tr>
          ))}
        </Table>
        <p className="mt-3 text-xs text-slate-600 dark:text-slate-400">
          Read-only. Addresses 0.0.0.0 and :: accept connections on every interface, also around the proxy.
          {can("containers.read") && (
            <>
              {" "}
              Docker networks are listed under{" "}
              <Link to="/networks" className={link}>
                Networks
              </Link>
              .
            </>
          )}
        </p>
      </Card>
    </div>
  );
}

/** ProxyPage manages reverse proxy routes and shows the host network (AT-F11-01..04). */
export function ProxyPage() {
  const { can } = useSession();
  const manage = can("network.manage");
  const { data, error, loading, reload } = useData(() => api.get<{ routes: ProxyRoute[]; proxy: ProxyState }>("/network/routes"), []);
  const [editing, setEditing] = useState<ProxyRoute | "new" | null>(null);
  const [deleting, setDeleting] = useState<ProxyRoute | null>(null);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  if (loading && !data) return <Spinner />;
  if (!data) return <Alert>{error ?? "The routes could not be loaded."}</Alert>;
  const st = data.proxy;

  return (
    <>
      <PageHeader
        title="Reverse proxy"
        description="Publish apps under their own host names, with access control per route."
        actions={
          manage &&
          st.configured && (
            <Button onClick={() => setEditing("new")} disabled={!st.reachable}>
              Add a route
            </Button>
          )
        }
      />
      <div className="space-y-4">
        {notice && <Alert kind={notice.kind}>{notice.text}</Alert>}
        <StatusCard st={st} manage={manage} onApplied={() => void reload()} />
        <Card title="Routes">
          {data.routes.length === 0 ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">No routes yet. Apps can get one when they are installed.</p>
          ) : (
            <Table
              caption="Routes"
              head={
                <tr>
                  <th className={th}>Address</th>
                  <th className={th}>Target</th>
                  <th className={th}>Access</th>
                  {manage && (
                    <th className={th}>
                      <span className="sr-only">Actions</span>
                    </th>
                  )}
                </tr>
              }
            >
              {data.routes.map((r) => (
                <tr key={r.id}>
                  <td className={td}>
                    <a href={r.url} target="_blank" rel="noopener noreferrer" className={link}>
                      {r.host}
                      {r.path_prefix}
                    </a>
                  </td>
                  <td className={td}>
                    {r.app ? (
                      <Link to={`/apps/${r.app}`} className={link}>
                        {r.app}
                      </Link>
                    ) : (
                      "port"
                    )}{" "}
                    <span className="text-slate-600 dark:text-slate-400">127.0.0.1:{r.upstream_port}</span>
                    {r.strip_prefix && <span className="text-slate-600 dark:text-slate-400"> (prefix removed)</span>}
                  </td>
                  <td className={td}>
                    <Access r={r} />
                  </td>
                  {manage && (
                    <td className={td}>
                      <span className="flex gap-1">
                        <Button variant="ghost" onClick={() => setEditing(r)}>
                          Edit <span className="sr-only">{`${r.host}${r.path_prefix}`}</span>
                        </Button>
                        <Button variant="ghost-danger" onClick={() => setDeleting(r)}>
                          Delete <span className="sr-only">{`${r.host}${r.path_prefix}`}</span>
                        </Button>
                      </span>
                    </td>
                  )}
                </tr>
              ))}
            </Table>
          )}
        </Card>
        {st.configured && <Overview />}
      </div>
      {editing && (
        <RouteDialog
          key={editing === "new" ? "new" : editing.id}
          route={editing === "new" ? null : editing}
          open
          onClose={() => setEditing(null)}
          onSaved={(text) => {
            setEditing(null);
            setNotice({ kind: "success", text });
            void reload();
          }}
        />
      )}
      <Dialog open={deleting !== null} title={`Delete ${deleting?.host ?? ""}${deleting?.path_prefix ?? ""}?`} onClose={() => setDeleting(null)}>
        <div className="space-y-4">
          <p className="text-sm">The address stops working at once. The app itself keeps running.</p>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              busy={busy}
              onClick={async () => {
                if (!deleting) return;
                setBusy(true);
                try {
                  await api.del(`/network/routes/${deleting.id}`);
                  setNotice({ kind: "success", text: `${deleting.host}${deleting.path_prefix} was deleted.` });
                } catch (err) {
                  setNotice({ kind: "error", text: errorMessage(err) });
                } finally {
                  setBusy(false);
                  setDeleting(null);
                  void reload();
                }
              }}
            >
              Delete route
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
