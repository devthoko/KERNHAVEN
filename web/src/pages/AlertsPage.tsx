import { useState } from "react";
import { Alert, Badge, Button, Card, Dialog, DotBadge, PageHeader, SelectField, Spinner, Table, TextField, capitalize, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime, formatRelative } from "../lib/format";
import { useSession } from "../lib/session";
import type { Alert as AlertItem, AlertRule, ChannelConfig, ChannelKind, Delivery, NotifyChannel } from "../lib/types";
import { useData } from "../lib/useData";

const kindLabel: Record<ChannelKind, string> = { smtp: "E-mail", webhook: "Webhook", ntfy: "ntfy", gotify: "Gotify" };
const secretLabel: Record<ChannelKind, string> = { smtp: "SMTP password", webhook: "Signing secret (optional)", ntfy: "Access token (optional)", gotify: "Application token" };
const paramLabel: Record<string, string> = {
  checks: "Failed checks in a row",
  percent: "Threshold (%)",
  minutes: "Minutes",
  failed_logins: "Failed sign-ins",
};
const deliveryTone = { sent: "green", pending: "blue", failed: "red", dropped: "amber" } as const;

/** AlertList shows alerts; used on the dashboard for the firing ones. */
export function AlertList({ alerts, empty }: { alerts: AlertItem[]; empty: string }) {
  if (alerts.length === 0) return <p className="text-sm text-slate-600 dark:text-slate-400">{empty}</p>;
  return (
    <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800" aria-label="Alerts">
      {alerts.map((a) => (
        <li key={a.id} className="space-y-1 py-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={a.state === "resolved" ? "green" : a.severity === "critical" ? "red" : "amber"}>{capitalize(a.state === "resolved" ? "resolved" : a.severity)}</Badge>
            <span className="font-medium">{a.title}</span>
            <span className="text-xs text-slate-600 dark:text-slate-400" title={formatDateTime(a.fired_at)}>
              {formatRelative(a.fired_at)}
            </span>
          </div>
          <p className="text-slate-600 dark:text-slate-400">{a.body}</p>
        </li>
      ))}
    </ul>
  );
}

function ChannelDialog({ channel, open, onClose, onSaved }: { channel: NotifyChannel | null; open: boolean; onClose: () => void; onSaved: (text: string) => void }) {
  const [name, setName] = useState(channel?.name ?? "");
  const [kind, setKind] = useState<ChannelKind>(channel?.kind ?? "ntfy");
  const [cfg, setCfg] = useState<ChannelConfig>(channel?.config ?? { security: "starttls", port: 587 });
  const [to, setTo] = useState((channel?.config.to ?? []).join(", "));
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (p: Partial<ChannelConfig>) => setCfg({ ...cfg, ...p });
  const save = async () => {
    setBusy(true);
    setError(null);
    const config = kind === "smtp" ? { ...cfg, to: to.split(/[\s,;]+/).filter(Boolean), url: undefined, topic: undefined } : { url: cfg.url, topic: kind === "ntfy" ? cfg.topic : undefined };
    const body = { name, kind, config, secret: secret === "" && channel ? null : secret };
    try {
      if (channel) await api.put(`/notify/channels/${channel.id}`, body);
      else await api.post("/notify/channels", body);
      onSaved(`${name} was saved. Send a test message to check it.`);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} title={channel ? `Edit ${channel.name}` : "Add a channel"} onClose={onClose}>
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
          <SelectField label="Kind" value={kind} disabled={!!channel} onChange={(e) => setKind(e.target.value as ChannelKind)}>
            {(Object.keys(kindLabel) as ChannelKind[]).map((k) => (
              <option key={k} value={k}>
                {kindLabel[k]}
              </option>
            ))}
          </SelectField>
        </div>
        {kind === "smtp" ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <TextField label="SMTP server" required autoCapitalize="none" value={cfg.host ?? ""} onChange={(e) => set({ host: e.target.value })} />
            <TextField label="Port" type="number" min={1} max={65535} value={cfg.port ?? 587} onChange={(e) => set({ port: Number(e.target.value) })} />
            <SelectField label="Security" value={cfg.security ?? "starttls"} onChange={(e) => set({ security: e.target.value as ChannelConfig["security"] })}>
              <option value="starttls">STARTTLS</option>
              <option value="tls">TLS</option>
              <option value="none">None (no sign-in)</option>
            </SelectField>
            <TextField label="Username (optional)" autoComplete="off" value={cfg.username ?? ""} onChange={(e) => set({ username: e.target.value })} />
            <TextField label="From" type="email" required value={cfg.from ?? ""} onChange={(e) => set({ from: e.target.value })} />
            <TextField label="To" hint="Up to 10 addresses, separated by commas" required value={to} onChange={(e) => setTo(e.target.value)} />
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2">
            <TextField
              label={kind === "webhook" ? "Webhook URL" : "Server URL"}
              hint={kind === "ntfy" ? "For example https://ntfy.sh or your own server" : undefined}
              required
              autoCapitalize="none"
              spellCheck={false}
              value={cfg.url ?? ""}
              onChange={(e) => set({ url: e.target.value })}
            />
            {kind === "ntfy" && <TextField label="Topic" required autoCapitalize="none" spellCheck={false} value={cfg.topic ?? ""} onChange={(e) => set({ topic: e.target.value })} />}
          </div>
        )}
        <TextField
          label={secretLabel[kind]}
          type="password"
          autoComplete="off"
          hint={channel?.has_secret ? "Stored. Leave empty to keep it." : "Stored encrypted and never shown again."}
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
        />
        <p className="text-xs text-slate-600 dark:text-slate-400">Addresses in your network are fine; loopback and link-local addresses are refused.</p>
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

function RuleRow({ rule, channels, manage, onSaved }: { rule: AlertRule; channels: NotifyChannel[]; manage: boolean; onSaved: (text: string, ok: boolean) => void }) {
  const [enabled, setEnabled] = useState(rule.enabled);
  const [params, setParams] = useState(rule.params);
  const [chans, setChans] = useState(rule.channels);
  const [busy, setBusy] = useState(false);
  const dirty = enabled !== rule.enabled || JSON.stringify(params) !== JSON.stringify(rule.params) || JSON.stringify([...chans].sort()) !== JSON.stringify([...rule.channels].sort());
  return (
    <li className="space-y-2 py-3">
      <label className="flex items-center gap-2 text-sm font-medium">
        <input type="checkbox" className="size-4" disabled={!manage} checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        {rule.title}
      </label>
      <div className="flex flex-wrap items-end gap-3 pl-6">
        {Object.entries(params).map(([k, v]) => (
          <div key={k} className="w-36">
            <TextField label={paramLabel[k] ?? k} type="number" disabled={!manage} value={v} onChange={(e) => setParams({ ...params, [k]: Number(e.target.value) })} />
          </div>
        ))}
        <fieldset className="flex flex-wrap gap-3 text-sm">
          <legend className="sr-only">Channels for {rule.title}</legend>
          {channels.length === 0 && <span className="text-slate-600 dark:text-slate-400">No channels yet — alerts are shown here only.</span>}
          {channels.map((c) => (
            <label key={c.id} className="flex items-center gap-1">
              <input
                type="checkbox"
                className="size-4"
                disabled={!manage}
                checked={chans.includes(c.id)}
                onChange={(e) => setChans(e.target.checked ? [...chans, c.id] : chans.filter((x) => x !== c.id))}
              />
              {c.name}
            </label>
          ))}
        </fieldset>
        {manage && dirty && (
          <Button
            variant="secondary"
            busy={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api.put(`/alerts/rules/${rule.rule}`, { enabled, params, channels: chans });
                onSaved(`“${rule.title}” was saved.`, true);
              } catch (err) {
                onSaved(errorMessage(err), false);
              } finally {
                setBusy(false);
              }
            }}
          >
            Save <span className="sr-only">{rule.title}</span>
          </Button>
        )}
      </div>
    </li>
  );
}

/** AlertsPage shows alerts, rules, channels and the delivery log (AT-F16-01..03). */
export function AlertsPage() {
  const { can } = useSession();
  const manage = can("alerts.manage");
  const alerts = useData(() => api.get<{ alerts: AlertItem[] }>("/alerts"), [], { refreshMs: 15000, live: ["alerts"] });
  const rules = useData(() => api.get<{ rules: AlertRule[] }>("/alerts/rules"), []);
  const channels = useData(() => api.get<{ channels: NotifyChannel[] }>("/notify/channels"), []);
  const deliveries = useData(() => api.get<{ deliveries: Delivery[] }>("/alerts/deliveries"), [], { refreshMs: 15000 });
  const [editing, setEditing] = useState<NotifyChannel | "new" | null>(null);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState<number | null>(null);

  if (!alerts.data || !rules.data || !channels.data) return alerts.error || rules.error || channels.error ? <Alert>{alerts.error ?? rules.error ?? channels.error}</Alert> : <Spinner />;
  const firing = alerts.data.alerts.filter((a) => a.state === "firing");
  const reloadAll = () => {
    void alerts.reload();
    void rules.reload();
    void channels.reload();
    void deliveries.reload();
  };

  return (
    <>
      <PageHeader title="Alerts" description="What Kernhaven noticed, and where it tells you." />
      <div className="space-y-4">
        {notice && <Alert kind={notice.kind}>{notice.text}</Alert>}
        <Card title={`Active (${firing.length})`}>
          <AlertList alerts={firing} empty="Nothing is wrong right now." />
        </Card>
        <Card
          title="Channels"
          actions={
            manage && (
              <Button variant="secondary" onClick={() => setEditing("new")}>
                Add a channel
              </Button>
            )
          }
        >
          {channels.data.channels.length === 0 ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">No channels. Add e-mail, a webhook, ntfy or Gotify to be notified.</p>
          ) : (
            <Table
              caption="Notification channels"
              head={
                <tr>
                  <th className={th}>Name</th>
                  <th className={th}>Kind</th>
                  <th className={th}>Destination</th>
                  {manage && (
                    <th className={th}>
                      <span className="sr-only">Actions</span>
                    </th>
                  )}
                </tr>
              }
            >
              {channels.data.channels.map((c) => (
                <tr key={c.id}>
                  <td className={td}>{c.name}</td>
                  <td className={td}>{kindLabel[c.kind]}</td>
                  <td className={`${td} break-all font-mono text-xs`}>{c.kind === "smtp" ? `${c.config.host}:${c.config.port} → ${(c.config.to ?? []).join(", ")}` : `${c.config.url}${c.config.topic ? `/${c.config.topic}` : ""}`}</td>
                  {manage && (
                    <td className={td}>
                      <span className="flex gap-1">
                        <Button
                          variant="ghost"
                          busy={busy === c.id}
                          onClick={async () => {
                            setBusy(c.id);
                            try {
                              const d = await api.post<Delivery>(`/notify/channels/${c.id}/test`);
                              setNotice(d.status === "sent" ? { kind: "success", text: `Test message sent to ${c.name}.` } : { kind: "error", text: `${c.name}: ${d.last_error ?? d.status}` });
                            } catch (err) {
                              setNotice({ kind: "error", text: errorMessage(err) });
                            } finally {
                              setBusy(null);
                              void deliveries.reload();
                            }
                          }}
                        >
                          Send test <span className="sr-only">to {c.name}</span>
                        </Button>
                        <Button variant="ghost" onClick={() => setEditing(c)}>
                          Edit <span className="sr-only">{c.name}</span>
                        </Button>
                        <Button
                          variant="ghost-danger"
                          onClick={async () => {
                            try {
                              await api.del(`/notify/channels/${c.id}`);
                              setNotice({ kind: "success", text: `${c.name} was deleted.` });
                              reloadAll();
                            } catch (err) {
                              setNotice({ kind: "error", text: errorMessage(err) });
                            }
                          }}
                        >
                          Delete <span className="sr-only">{c.name}</span>
                        </Button>
                      </span>
                    </td>
                  )}
                </tr>
              ))}
            </Table>
          )}
        </Card>
        <Card title="Rules">
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {rules.data.rules.map((r) => (
              <RuleRow
                key={`${r.rule}-${JSON.stringify(r)}`}
                rule={r}
                channels={channels.data!.channels}
                manage={manage}
                onSaved={(text, ok) => {
                  setNotice({ kind: ok ? "success" : "error", text });
                  if (ok) void rules.reload();
                }}
              />
            ))}
          </ul>
        </Card>
        <Card title="History">
          <AlertList alerts={alerts.data.alerts.filter((a) => a.state !== "firing").slice(0, 50)} empty="No alerts yet." />
        </Card>
        <Card title="Delivery log">
          {deliveries.data && deliveries.data.deliveries.length > 0 ? (
            <Table
              caption="Delivery log"
              head={
                <tr>
                  <th className={th}>When</th>
                  <th className={th}>Message</th>
                  <th className={th}>Channel</th>
                  <th className={th}>Status</th>
                </tr>
              }
            >
              {deliveries.data.deliveries.map((d) => (
                <tr key={d.id}>
                  <td className={td}>{formatDateTime(d.created_at)}</td>
                  <td className={td}>
                    {d.kind === "resolve" ? "Resolved: " : ""}
                    {d.title}
                  </td>
                  <td className={td}>{d.channel}</td>
                  <td className={td}>
                    <DotBadge tone={deliveryTone[d.status]}>{capitalize(d.status)}</DotBadge> {d.attempts > 1 && <span className="text-xs">({d.attempts} attempts)</span>}
                    {d.status === "pending" && d.next_at && <span className="text-xs"> next {formatRelative(d.next_at)}</span>}
                    {d.last_error && <div className="max-w-md whitespace-normal text-xs text-red-700 dark:text-red-400">{d.last_error}</div>}
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            <p className="text-sm text-slate-600 dark:text-slate-400">Nothing sent yet.</p>
          )}
        </Card>
      </div>
      {editing && (
        <ChannelDialog
          key={editing === "new" ? "new" : editing.id}
          channel={editing === "new" ? null : editing}
          open
          onClose={() => setEditing(null)}
          onSaved={(text) => {
            setEditing(null);
            setNotice({ kind: "success", text });
            reloadAll();
          }}
        />
      )}
    </>
  );
}
