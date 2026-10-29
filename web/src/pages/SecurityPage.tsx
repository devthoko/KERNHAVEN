import { Alert, Badge, Card, PageHeader, Spinner, Table, td, th } from "../components/ui";
import { api } from "../lib/api";
import { formatDateTime, formatRelative, roleLabel } from "../lib/format";
import type { SecurityOverview } from "../lib/types";
import { Link } from "../lib/router";
import { useData } from "../lib/useData";

const tone = { critical: "red", warning: "amber", info: "blue" } as const;

function Stat({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="rounded-md border border-slate-200 p-3 dark:border-slate-700">
      <div className="text-xs text-slate-600 dark:text-slate-400">{label}</div>
      <div className="text-xl font-semibold">{value}</div>
      {note && <div className="text-xs text-slate-600 dark:text-slate-400">{note}</div>}
    </div>
  );
}

/** SecurityPage is the security dashboard (AT-F10-04). */
export function SecurityPage() {
  const { data, error } = useData(() => api.get<SecurityOverview>("/security/overview"), [], { refreshMs: 60000 });
  if (!data) return error ? <Alert>{error}</Alert> : <Spinner />;
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const f of data.findings) counts[f.severity]++;
  const exposed = data.routes.filter((r) => r.unprotected).length;
  return (
    <>
      <PageHeader title="Security" description="What deserves a look, with a link to where it is fixed." />
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <Stat label="Second factor" value={`${data.mfa.covered} of ${data.mfa.users}`} note="accounts with a passkey or authenticator app" />
          <Stat label="Published routes" value={String(data.routes.length)} note={`${exposed} open to anyone`} />
          <Stat label="Policy exceptions" value={String(data.exceptions.length)} note="in deployed stacks" />
          <Stat label="Failed sign-ins" value={String(data.logins.failed_24h)} note={`last 24 hours, ${data.logins.lockouts_24h} lockouts`} />
          <Stat label="Audit log" value={data.audit.ok ? "intact" : "broken"} note={`${data.audit.records} records`} />
        </div>
        <Card title={`Findings (${counts.critical} critical, ${counts.warning} warnings)`}>
          {data.findings.length === 0 ? (
            <p className="text-sm text-slate-600 dark:text-slate-400">Nothing to report.</p>
          ) : (
            <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800" aria-label="Findings">
              {data.findings.map((f, i) => (
                <li key={i} className="flex flex-wrap items-center gap-2 py-2">
                  <Badge tone={tone[f.severity]}>{f.severity}</Badge>
                  <span>{f.title}</span>
                  <Link to={f.link} className="font-medium text-brand-700 underline dark:text-brand-500">
                    Open <span className="sr-only">{f.title}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Accounts">
            <Table
              caption="Second factors by account"
              head={
                <tr>
                  <th className={th}>User</th>
                  <th className={th}>Role</th>
                  <th className={th}>Second factor</th>
                </tr>
              }
            >
              {data.mfa.accounts.map((u) => (
                <tr key={u.username}>
                  <td className={td}>{u.username}</td>
                  <td className={td}>
                    {roleLabel(u.role)} {data.mfa.policy[u.role] && <span className="text-xs text-slate-600 dark:text-slate-400">(required)</span>}
                  </td>
                  <td className={td}>
                    {u.passkeys > 0 || u.totp ? (
                      <Badge tone="green">{[u.passkeys > 0 ? `${u.passkeys} passkey${u.passkeys > 1 ? "s" : ""}` : "", u.totp ? "app" : ""].filter(Boolean).join(" + ")}</Badge>
                    ) : (
                      <Badge tone={u.role === "owner" || u.role === "admin" || u.required ? "red" : "gray"}>none</Badge>
                    )}
                  </td>
                </tr>
              ))}
            </Table>
          </Card>
          <Card title="Published routes">
            {data.routes.length === 0 ? (
              <p className="text-sm text-slate-600 dark:text-slate-400">No app is published through the reverse proxy.</p>
            ) : (
              <Table
                caption="Routes and their protection"
                head={
                  <tr>
                    <th className={th}>Address</th>
                    <th className={th}>Protection</th>
                  </tr>
                }
              >
                {data.routes.map((r) => (
                  <tr key={r.host + r.path}>
                    <td className={`${td} break-all`}>
                      {r.host}
                      {r.path}
                    </td>
                    <td className={td}>
                      {r.unprotected ? (
                        <Badge tone="amber">open to anyone</Badge>
                      ) : (
                        [r.sign_in && "Kernhaven sign-in", r.lan_only && "LAN only", r.allow_list && "address list"].filter(Boolean).join(", ")
                      )}
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
          <Card title="Policy exceptions">
            {data.exceptions.length === 0 ? (
              <p className="text-sm text-slate-600 dark:text-slate-400">No deployed stack runs with an exception.</p>
            ) : (
              <Table
                caption="Approved policy exceptions"
                head={
                  <tr>
                    <th className={th}>Service</th>
                    <th className={th}>Rule</th>
                    <th className={th}>Reason</th>
                  </tr>
                }
              >
                {data.exceptions.map((e) => (
                  <tr key={`${e.stack}/${e.service}/${e.rule}`}>
                    <td className={td}>
                      {e.stack}/{e.service}
                    </td>
                    <td className={`${td} font-mono text-xs`}>{e.rule}</td>
                    <td className={td}>
                      {e.reason} <span className="text-xs text-slate-600 dark:text-slate-400">— {e.approved_by}</span>
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
          <Card title="Updates">
            {data.updates.length === 0 && data.old_images.length === 0 ? (
              <p className="text-sm text-slate-600 dark:text-slate-400">
                All apps run their catalog&apos;s version{data.images_checked ? " and no running image is older than 180 days" : ""}.
              </p>
            ) : (
              <ul className="space-y-1 text-sm">
                {data.updates.map((a) => (
                  <li key={a.name}>
                    {a.name}: {a.version} → {a.latest_version}
                  </li>
                ))}
                {data.old_images.map((im) => (
                  <li key={im.image}>
                    {im.image}: built {formatRelative(im.created)}, {im.containers} running
                  </li>
                ))}
              </ul>
            )}
            {!data.images_checked && <p className="mt-2 text-xs text-slate-600 dark:text-slate-400">Images were not checked (Docker agent unavailable).</p>}
          </Card>
          <Card title="Failed sign-ins (24 hours)">
            {data.logins.recent.length === 0 ? (
              <p className="text-sm text-slate-600 dark:text-slate-400">None.</p>
            ) : (
              <>
                <p className="mb-2 text-sm">
                  By address:{" "}
                  {Object.entries(data.logins.by_source)
                    .map(([ip, n]) => `${ip || "unknown"} (${n})`)
                    .join(", ")}
                </p>
                <ul className="space-y-1 text-sm">
                  {data.logins.recent.map((e) => (
                    <li key={e.seq}>
                      {formatDateTime(e.time)} — {e.actor} from {e.ip || "unknown"}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </Card>
          <Card title="Certificates and backups">
            <ul className="space-y-1 text-sm">
              {data.certificates.length === 0 && <li>No uploaded or DNS-01 certificates (Caddy renews the others).</li>}
              {data.certificates.map((c) => (
                <li key={c.id}>
                  {c.names.join(", ")}: expires {formatDateTime(c.not_after)} {c.hosts.length === 0 && <span className="text-xs text-slate-600 dark:text-slate-400">(not in use)</span>}
                </li>
              ))}
              <li>
                Backups: {data.backup.plans} enabled plan{data.backup.plans === 1 ? "" : "s"}, last success {data.backup.last_succeeded ? formatRelative(data.backup.last_succeeded) : "never"}
              </li>
            </ul>
          </Card>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400">Updated {formatDateTime(data.generated_at)}.</p>
      </div>
    </>
  );
}
