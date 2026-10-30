import { useId, useState, type ChangeEvent } from "react";
import { Alert, Badge, Button, Card, Dialog, PageHeader, SelectField, Spinner, Table, TextField, buttonClass, inputClass, link, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { Link } from "../lib/router";
import { useSession } from "../lib/session";
import type { HostTLS, StoredCertificate, TLSMode, TLSOverview, TLSSettings } from "../lib/types";
import { useData } from "../lib/useData";

const DAY = 24 * 60 * 60 * 1000;

const modeLabel: Record<TLSMode, string> = {
  internal: "Kernhaven CA",
  acme: "Let's Encrypt (HTTP)",
  dns: "Let's Encrypt (DNS)",
  custom: "Own certificate",
};

function Expiry({ notAfter }: { notAfter: string }) {
  const days = Math.floor((new Date(notAfter).getTime() - Date.now()) / DAY);
  if (days < 0) return <Badge tone="red">Expired</Badge>;
  if (days < 30) return <Badge tone="amber">{days} days left</Badge>;
  return <span>{formatDateTime(notAfter)}</span>;
}

/** RootCard offers the internal CA's root for client trust (AT-F12-02). */
export function RootCard({ sha256 }: { sha256?: string }) {
  return (
    <Card title="Trust this server">
      <div className="space-y-3 text-sm">
        <p>
          Hosts without a public certificate use Kernhaven's own certificate authority. Install its root certificate on your devices once and the browser warnings
          disappear.
        </p>
        <a href="/api/v1/tls/root.crt" download className={buttonClass("primary", "w-fit")}>
          Download root certificate
        </a>
        {sha256 && (
          <p className="break-all text-xs text-slate-600 dark:text-slate-400">
            Check the fingerprint on the device (SHA-256): <span className="font-mono">{sha256.match(/.{2}/g)?.join(":")}</span>
          </p>
        )}
      </div>
    </Card>
  );
}

function SettingsCard({ st, manage, onSaved }: { st: TLSSettings; manage: boolean; onSaved: () => void }) {
  const [form, setForm] = useState({ email: st.email, ca: st.ca, agree_tos: !!st.agreed_at, dns_provider: st.dns_provider });
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  return (
    <Card title="Let's Encrypt">
      <form
        className="space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setNotice(null);
          try {
            await api.put("/tls/settings", { ...form, cloudflare_token: token === "" ? null : token });
            setToken("");
            setNotice({ kind: "success", text: "The settings were saved." });
            onSaved();
          } catch (err) {
            setNotice({ kind: "error", text: errorMessage(err) });
          } finally {
            setBusy(false);
          }
        }}
      >
        {notice && <Alert kind={notice.kind}>{notice.text}</Alert>}
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField label="Contact e-mail" type="email" autoComplete="email" disabled={!manage} value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <SelectField label="Certificate authority" disabled={!manage} value={form.ca} onChange={(e) => setForm({ ...form, ca: e.target.value as TLSSettings["ca"] })}>
            <option value="production">Let's Encrypt</option>
            <option value="staging">Let's Encrypt staging (test certificates)</option>
          </SelectField>
        </div>
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-1 size-4" disabled={!manage} checked={form.agree_tos} onChange={(e) => setForm({ ...form, agree_tos: e.target.checked })} />
          <span>
            I accept the{" "}
            <a href="https://letsencrypt.org/repository/" target="_blank" rel="noopener noreferrer" className={link}>
              Let&apos;s Encrypt Subscriber Agreement
            </a>
            .
          </span>
        </label>
        <div className="grid gap-4 sm:grid-cols-2">
          <SelectField label="DNS provider (for DNS-01)" disabled={!manage} value={form.dns_provider} onChange={(e) => setForm({ ...form, dns_provider: e.target.value as TLSSettings["dns_provider"] })}>
            <option value="">None</option>
            <option value="cloudflare">Cloudflare</option>
          </SelectField>
          {form.dns_provider === "cloudflare" && (
            <TextField
              label="Cloudflare API token"
              type="password"
              autoComplete="off"
              disabled={!manage}
              hint={st.dns_configured ? "A token is stored. Leave empty to keep it." : "A token with Zone · DNS · Edit for your zone."}
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          )}
        </div>
        {manage && (
          <Button type="submit" busy={busy}>
            Save
          </Button>
        )}
      </form>
    </Card>
  );
}

function HostDialog({ host, certs, open, onClose, onSaved }: { host: HostTLS; certs: StoredCertificate[]; open: boolean; onClose: () => void; onSaved: (text: string) => void }) {
  const [mode, setMode] = useState<TLSMode>(host.mode);
  // A wildcard covers exactly one label (the server checks this again).
  const covers = (n: string) => n === host.host || (n.startsWith("*.") && host.host.endsWith(n.slice(1)) && host.host.split(".").length === n.split(".").length);
  const usable = certs.filter((c) => c.source === "upload" && c.names.some(covers));
  const [cert, setCert] = useState<number>(host.certificate_id ?? usable[0]?.id ?? 0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <Dialog open={open} title={`Certificate for ${host.host}`} onClose={onClose}>
      <form
        className="space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            const res = await api.put<{ job_id?: number }>(`/tls/hosts/${encodeURIComponent(host.host)}`, { mode, certificate_id: mode === "custom" ? cert : 0 });
            onSaved(res.job_id ? `${host.host}: the certificate is being requested (job #${res.job_id}).` : `${host.host} uses ${modeLabel[mode]}.`);
          } catch (err) {
            setError(errorMessage(err));
            setBusy(false);
          }
        }}
      >
        {error && <Alert>{error}</Alert>}
        <fieldset className="space-y-2 text-sm">
          <legend className="mb-1 font-medium">Where the certificate comes from</legend>
          {(["internal", "acme", "dns", "custom"] as TLSMode[]).map((m) => (
            <label key={m} className="flex items-start gap-2">
              <input type="radio" name="mode" className="mt-1 size-4" checked={mode === m} onChange={() => setMode(m)} />
              <span>
                <span className="font-medium">{modeLabel[m]}</span>
                <span className="block text-slate-600 dark:text-slate-400">
                  {m === "internal" && "For the local network. Devices must trust the Kernhaven root certificate."}
                  {m === "acme" && "The host must be reachable from the internet on ports 80 and 443. Not for LAN-only routes."}
                  {m === "dns" && "For a domain in your DNS zone, also when the host is only reachable in the LAN. Needs the DNS provider."}
                  {m === "custom" && "A certificate you uploaded that covers this host."}
                </span>
              </span>
            </label>
          ))}
        </fieldset>
        {mode === "custom" &&
          (usable.length === 0 ? (
            <Alert kind="warning">No uploaded certificate covers {host.host}.</Alert>
          ) : (
            <SelectField label="Certificate" value={cert} onChange={(e) => setCert(Number(e.target.value))}>
              {usable.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.names.join(", ")} — until {formatDateTime(c.not_after)}
                </option>
              ))}
            </SelectField>
          ))}
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" busy={busy} disabled={mode === "custom" && usable.length === 0}>
            Apply
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function UploadDialog({ open, onClose, onSaved }: { open: boolean; onClose: () => void; onSaved: (text: string) => void }) {
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const certId = useId();
  const keyId = useId();
  const area = `${inputClass} font-mono text-xs`;
  const load = (set: (v: string) => void) => (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) void f.text().then(set);
  };
  return (
    <Dialog open={open} title="Upload a certificate" onClose={onClose}>
      <form
        className="space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            const c = await api.post<StoredCertificate>("/tls/certificates", { certificate_pem: cert, key_pem: key });
            onSaved(`The certificate for ${c.names.join(", ")} was stored. Assign it to a host to use it.`);
          } catch (err) {
            setError(errorMessage(err));
            setBusy(false);
          }
        }}
      >
        {error && <Alert>{error}</Alert>}
        <div className="space-y-1">
          <label htmlFor={certId} className="block text-sm font-medium">
            Certificate chain (PEM, server certificate first)
          </label>
          <textarea id={certId} rows={5} spellCheck={false} className={area} value={cert} onChange={(e) => setCert(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
          <input type="file" accept=".pem,.crt,.cer" aria-label="Certificate file" className="text-xs" onChange={load(setCert)} />
        </div>
        <div className="space-y-1">
          <label htmlFor={keyId} className="block text-sm font-medium">
            Private key (PEM, without passphrase)
          </label>
          <textarea id={keyId} rows={4} spellCheck={false} className={area} value={key} onChange={(e) => setKey(e.target.value)} placeholder="PEM key (PKCS#8, RSA or EC)" />
          <input type="file" accept=".pem,.key" aria-label="Key file" className="text-xs" onChange={load(setKey)} />
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400">
          Checked before it is stored: the key belongs to the certificate, the chain leads to a trusted root (include your own CA&apos;s root), and the certificate is
          valid. The key is stored encrypted and never shown again.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" busy={busy} disabled={!cert.trim() || !key.trim()}>
            Upload
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/** CertificatesPage manages TLS per host (AT-F12-01..03). */
export function CertificatesPage() {
  const { can } = useSession();
  const manage = can("network.manage");
  const { data, error, loading, reload } = useData(() => api.get<TLSOverview>("/tls"), [], { refreshMs: 5000 });
  const [editing, setEditing] = useState<HostTLS | null>(null);
  const [uploading, setUploading] = useState(false);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);

  if (loading && !data) return <Spinner />;
  if (!data) return <Alert>{error ?? "The certificates could not be loaded."}</Alert>;
  const saved = (text: string) => {
    setEditing(null);
    setUploading(false);
    setNotice({ kind: "success", text });
    void reload();
  };
  const certById = new Map(data.certificates.map((c) => [c.id, c]));

  return (
    <>
      <PageHeader
        title="Certificates"
        description="HTTPS certificates for Kernhaven and every published host."
        actions={
          manage && (
            <Button variant="secondary" onClick={() => setUploading(true)}>
              Upload a certificate
            </Button>
          )
        }
      />
      <div className="space-y-4">
        {notice && <Alert kind={notice.kind}>{notice.text}</Alert>}
        <Card title="Hosts">
          <Table
            caption="Hosts and their certificates"
            head={
              <tr>
                <th className={th}>Host</th>
                <th className={th}>Certificate</th>
                <th className={th}>Valid until</th>
                {manage && (
                  <th className={th}>
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            }
          >
            {data.hosts.map((h) => {
              const c = h.certificate_id ? certById.get(h.certificate_id) : undefined;
              return (
                <tr key={h.host}>
                  <td className={td}>
                    {h.host} {h.kernhaven && <Badge tone="blue">Kernhaven</Badge>} {h.lan_only && <Badge>LAN only</Badge>}
                  </td>
                  <td className={td}>
                    {modeLabel[h.effective]}
                    {h.mode !== h.effective && <span className="text-slate-600 dark:text-slate-400"> (waiting for {modeLabel[h.mode]})</span>}
                    {h.error && (
                      <div className="max-w-md whitespace-normal text-xs text-red-700 dark:text-red-400">
                        Last attempt failed{h.error_at ? ` (${formatDateTime(h.error_at)})` : ""}: {h.error}
                      </div>
                    )}
                  </td>
                  <td className={td}>{c ? <Expiry notAfter={c.not_after} /> : h.effective === "internal" || h.effective === "acme" ? "renewed by Caddy" : "—"}</td>
                  {manage && (
                    <td className={td}>
                      <span className="flex gap-1">
                        <Button variant="ghost" onClick={() => setEditing(h)}>
                          Change <span className="sr-only">{h.host}</span>
                        </Button>
                        {h.mode === "dns" && (
                          <Button
                            variant="ghost"
                            onClick={async () => {
                              try {
                                const r = await api.post<{ job_id: number }>(`/tls/hosts/${encodeURIComponent(h.host)}/renew`);
                                setNotice({ kind: "success", text: `Requesting a new certificate for ${h.host} (job #${r.job_id}).` });
                              } catch (err) {
                                setNotice({ kind: "error", text: errorMessage(err) });
                              }
                            }}
                          >
                            Renew <span className="sr-only">{h.host}</span>
                          </Button>
                        )}
                      </span>
                    </td>
                  )}
                </tr>
              );
            })}
          </Table>
          {can("network.read") && (
            <p className="mt-3 text-xs text-slate-600 dark:text-slate-400">
              Hosts come from the{" "}
              <Link to="/proxy" className={link}>
                reverse proxy routes
              </Link>
              .
            </p>
          )}
        </Card>
        <Card title="Stored certificates">
          {data.certificates.length === 0 ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">No uploaded or DNS-01 certificates.</p>
          ) : (
            <Table
              caption="Stored certificates"
              head={
                <tr>
                  <th className={th}>Names</th>
                  <th className={th}>Issuer</th>
                  <th className={th}>Valid until</th>
                  <th className={th}>Used by</th>
                  {manage && (
                    <th className={th}>
                      <span className="sr-only">Actions</span>
                    </th>
                  )}
                </tr>
              }
            >
              {data.certificates.map((c) => (
                <tr key={c.id}>
                  <td className={td}>
                    {c.names.join(", ")} <Badge>{c.source === "dns" ? "DNS-01" : "Uploaded"}</Badge>
                  </td>
                  <td className={`${td} max-w-xs truncate`} title={c.issuer}>
                    {c.issuer}
                  </td>
                  <td className={td}>
                    <Expiry notAfter={c.not_after} />
                  </td>
                  <td className={td}>{c.hosts.length ? c.hosts.join(", ") : "—"}</td>
                  {manage && (
                    <td className={td}>
                      {c.hosts.length === 0 && (
                        <Button
                          variant="ghost-danger"
                          onClick={async () => {
                            try {
                              await api.del(`/tls/certificates/${c.id}`);
                              setNotice({ kind: "success", text: "The certificate was deleted." });
                              void reload();
                            } catch (err) {
                              setNotice({ kind: "error", text: errorMessage(err) });
                            }
                          }}
                        >
                          Delete <span className="sr-only">{c.names.join(", ")}</span>
                        </Button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </Table>
          )}
        </Card>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <SettingsCard key={JSON.stringify(data.settings)} st={data.settings} manage={manage} onSaved={() => void reload()} />
          <RootCard sha256={data.root_sha256} />
        </div>
      </div>
      {editing && <HostDialog key={editing.host} host={editing} certs={data.certificates} open onClose={() => setEditing(null)} onSaved={saved} />}
      {uploading && <UploadDialog open onClose={() => setUploading(false)} onSaved={saved} />}
    </>
  );
}
