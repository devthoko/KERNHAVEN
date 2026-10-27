import { useState, type FormEvent } from "react";
import { Alert, Badge, Button, Card, PageHeader, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime, formatRelative, roleLabel } from "../lib/format";
import { useCurrentSession, useSession } from "../lib/session";
import type { Session, Theme } from "../lib/types";
import { useData } from "../lib/useData";

function PasswordCard() {
  const [form, setForm] = useState({ current: "", next: "", confirm: "" });
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const mismatch = form.confirm !== "" && form.next !== form.confirm;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setOk(false);
    try {
      await api.post("/auth/password", { current_password: form.current, new_password: form.next });
      setForm({ current: "", next: "", confirm: "" });
      setOk(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Change password">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {error && <Alert>{error}</Alert>}
        {ok && <Alert kind="success">Password changed. Your other sessions were signed out.</Alert>}
        <TextField label="Current password" type="password" autoComplete="current-password" value={form.current} onChange={(e) => setForm({ ...form, current: e.target.value })} />
        <TextField label="New password" type="password" autoComplete="new-password" value={form.next} onChange={(e) => setForm({ ...form, next: e.target.value })} hint="At least 12 characters." />
        <TextField label="Confirm new password" type="password" autoComplete="new-password" value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} error={mismatch ? "The passwords do not match." : undefined} />
        <Button type="submit" busy={busy} disabled={!form.current || !form.next || form.next !== form.confirm}>
          Change password
        </Button>
      </form>
    </Card>
  );
}

function SessionsCard() {
  const { logout } = useSession();
  const { data, error, loading, reload } = useData(() => api.get<{ sessions: Session[] }>("/auth/sessions"), []);
  const [actionError, setActionError] = useState<string | null>(null);
  const revoke = async (s: Session) => {
    setActionError(null);
    try {
      await api.del(`/auth/sessions/${encodeURIComponent(s.id)}`);
      if (s.current) await logout();
      else await reload();
    } catch (err) {
      setActionError(errorMessage(err));
    }
  };
  return (
    <Card title="Active sessions">
      {loading && !data && <Spinner />}
      {error && <Alert>{error}</Alert>}
      {actionError && <Alert>{actionError}</Alert>}
      {data && (
        <Table
          caption="Your active sessions"
          head={
            <tr>
              <th className={th}>Device</th>
              <th className={th}>Address</th>
              <th className={th}>Last active</th>
              <th className={th}>Signed in</th>
              <th className={th}>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          }
        >
          {data.sessions.map((s) => (
            <tr key={s.id}>
              <td className={`${td} max-w-64 truncate`} title={s.user_agent}>
                {s.user_agent || "Unknown"} {s.current && <Badge tone="blue">This device</Badge>}
              </td>
              <td className={td}>{s.ip}</td>
              <td className={td}>{formatRelative(s.last_seen_at)}</td>
              <td className={td}>{formatDateTime(s.created_at)}</td>
              <td className={`${td} text-right`}>
                <Button variant="ghost" aria-label={s.current ? "Sign out this device" : `Revoke session from ${s.ip}`} onClick={() => revoke(s)}>
                  {s.current ? "Sign out" : "Revoke"}
                </Button>
              </td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

const themes: { value: Theme; label: string }[] = [
  { value: "system", label: "System" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

function AppearanceCard() {
  const { theme, setTheme } = useSession();
  const [error, setError] = useState<string | null>(null);
  const change = async (t: Theme) => {
    setError(null);
    try {
      await setTheme(t);
    } catch (err) {
      setError(errorMessage(err));
    }
  };
  return (
    <Card title="Appearance">
      {error && <Alert>{error}</Alert>}
      <fieldset>
        <legend className="mb-2 text-sm text-slate-600 dark:text-slate-400">Theme (saved to your account)</legend>
        <div className="flex flex-wrap gap-4">
          {themes.map((t) => (
            <label key={t.value} className="flex items-center gap-2 text-sm">
              <input type="radio" name="theme" className="size-4" value={t.value} checked={theme === t.value} onChange={() => change(t.value)} />
              {t.label}
            </label>
          ))}
        </div>
      </fieldset>
    </Card>
  );
}

export function AccountPage() {
  const session = useCurrentSession();
  return (
    <>
      <PageHeader title="Account" description={`${session.user.username} · ${roleLabel(session.user.role)}`} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <PasswordCard />
        <AppearanceCard />
        <div className="lg:col-span-2">
          <SessionsCard />
        </div>
      </div>
    </>
  );
}
