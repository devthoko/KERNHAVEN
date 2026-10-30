import { useState, type FormEvent } from "react";
import { Alert, Avatar, Badge, Button, Card, Dialog, PageHeader, SelectField, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatDateTime, roleLabel } from "../lib/format";
import { canManage, useCurrentSession, useSession } from "../lib/session";
import { ROLES, type Role, type User } from "../lib/types";
import { useData } from "../lib/useData";

type DialogState =
  | { kind: "none" }
  | { kind: "create" }
  | { kind: "edit"; user: User }
  | { kind: "password"; user: User }
  | { kind: "delete"; user: User };

function assignableRoles(actor: Role): Role[] {
  return ROLES.filter((r) => canManage(actor, r));
}

function CreateUserForm({ actor, onDone }: { actor: Role; onDone: (u: User) => void }) {
  const roles = assignableRoles(actor);
  const [form, setForm] = useState({ username: "", display_name: "", role: roles[roles.length - 1] ?? "viewer", password: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(await api.post<User>("/users", { ...form, username: form.username.trim() }));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      {error && <Alert>{error}</Alert>}
      <TextField label="Username" autoCapitalize="none" spellCheck={false} required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} hint="3–32 characters: lowercase letters, digits, . _ -" />
      <TextField label="Display name (optional)" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
      <SelectField label="Role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
        {roles.map((r) => (
          <option key={r} value={r}>
            {roleLabel(r)}
          </option>
        ))}
      </SelectField>
      <TextField label="Initial password" type="password" autoComplete="new-password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} hint="At least 12 characters. Share it securely; the user can change it under Account." />
      <div className="flex justify-end">
        <Button type="submit" busy={busy} disabled={!form.username || !form.password}>
          Create user
        </Button>
      </div>
    </form>
  );
}

function EditUserForm({ actor, user, self, onDone }: { actor: Role; user: User; self: boolean; onDone: (u: User) => void }) {
  const [form, setForm] = useState({ display_name: user.display_name, role: user.role, disabled: user.disabled });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const roles = assignableRoles(actor);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const patch: Record<string, unknown> = { display_name: form.display_name };
    if (form.role !== user.role) patch.role = form.role;
    if (form.disabled !== user.disabled) patch.disabled = form.disabled;
    try {
      onDone(await api.patch<User>(`/users/${user.id}`, patch));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      {error && <Alert>{error}</Alert>}
      <TextField label="Display name" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
      <SelectField label="Role" value={form.role} disabled={self} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
        {(roles.includes(user.role) ? roles : [user.role, ...roles]).map((r) => (
          <option key={r} value={r}>
            {roleLabel(r)}
          </option>
        ))}
      </SelectField>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" className="size-4" checked={form.disabled} disabled={self} onChange={(e) => setForm({ ...form, disabled: e.target.checked })} />
        Account disabled
      </label>
      {self && <p className="text-xs text-slate-600 dark:text-slate-400">You cannot change your own role or disable yourself.</p>}
      {(form.role !== user.role || form.disabled !== user.disabled) && (
        <Alert kind="info">Changing the role or disabling the account signs the user out everywhere.</Alert>
      )}
      <div className="flex justify-end">
        <Button type="submit" busy={busy}>
          Save
        </Button>
      </div>
    </form>
  );
}

function ResetPasswordForm({ user, onDone }: { user: User; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post(`/users/${user.id}/password`, { password });
      onDone();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      {error && <Alert>{error}</Alert>}
      <p className="text-sm">
        Set a new password for <strong>{user.username}</strong>. All of their sessions end.
      </p>
      <TextField label="New password" type="password" autoComplete="new-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
      <div className="flex justify-end">
        <Button type="submit" busy={busy} disabled={!password}>
          Reset password
        </Button>
      </div>
    </form>
  );
}

function DeleteUserForm({ user, onDone }: { user: User; onDone: () => void }) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.del(`/users/${user.id}`);
      onDone();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      {error && <Alert>{error}</Alert>}
      <p className="text-sm">
        This permanently deletes <strong>{user.username}</strong> and ends their sessions. Audit records are kept.
      </p>
      <TextField label={`Type "${user.username}" to confirm`} autoCapitalize="none" spellCheck={false} value={typed} onChange={(e) => setTyped(e.target.value)} />
      <div className="flex justify-end">
        <Button type="submit" variant="danger" busy={busy} disabled={typed !== user.username}>
          Delete user
        </Button>
      </div>
    </form>
  );
}

export function UsersPage() {
  const session = useCurrentSession();
  const { can } = useSession();
  const actor = session.user.role;
  const { data, error, loading, reload } = useData(() => api.get<{ users: User[] }>("/users"), []);
  const [dialog, setDialog] = useState<DialogState>({ kind: "none" });
  const [notice, setNotice] = useState<string | null>(null);
  const close = () => setDialog({ kind: "none" });
  const done = (msg: string) => {
    close();
    setNotice(msg);
    void reload();
  };
  const manage = can("users.manage");

  return (
    <>
      <PageHeader
        title="Users"
        description="Accounts and roles. Owners manage everyone; admins manage operators and viewers."
        actions={manage ? <Button onClick={() => setDialog({ kind: "create" })}>New user</Button> : undefined}
      />
      {notice && (
        <div className="mb-4">
          <Alert kind="success">{notice}</Alert>
        </div>
      )}
      <Card>
        {loading && !data && <Spinner />}
        {error && <Alert>{error}</Alert>}
        {data && (
          <Table
            caption="Users"
            head={
              <tr>
                <th className={th}>User</th>
                <th className={th}>Role</th>
                <th className={th}>Status</th>
                <th className={th}>Created</th>
                {manage && (
                  <th className={th}>
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            }
          >
            {data.users.map((u) => {
              const self = u.id === session.user.id;
              const editable = manage && (self || canManage(actor, u.role));
              return (
                <tr key={u.id}>
                  <td className={td}>
                    <div className="flex items-center gap-3">
                      <Avatar name={u.display_name || u.username} className="size-8 text-xs" />
                      <div>
                        <div className="font-medium">{u.display_name || u.username}</div>
                        <div className="text-xs text-slate-600 dark:text-slate-400">
                          {u.username}
                          {self && " (you)"}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className={td}>{roleLabel(u.role)}</td>
                  <td className={td}>
                    {u.disabled ? <Badge tone="gray">Disabled</Badge> : u.locked ? <Badge tone="amber">Locked</Badge> : <Badge tone="green">Active</Badge>}
                  </td>
                  <td className={td}>{formatDateTime(u.created_at)}</td>
                  {manage && (
                    <td className={`${td} text-right`}>
                      {editable && (
                        <div className="flex justify-end gap-1">
                          <Button variant="ghost" aria-label={`Edit ${u.username}`} onClick={() => setDialog({ kind: "edit", user: u })}>
                            Edit
                          </Button>
                          {!self && (
                            <>
                              <Button variant="ghost" aria-label={`Reset password of ${u.username}`} onClick={() => setDialog({ kind: "password", user: u })}>
                                Password
                              </Button>
                              <Button
                                variant="ghost"
                                aria-label={`Reset MFA of ${u.username}`}
                                onClick={() =>
                                  api.post(`/users/${u.id}/mfa/reset`).then(
                                    () => done(`Second factors of ${u.username} were reset; password sign-in is on again.`),
                                    (err) => setNotice(errorMessage(err)),
                                  )
                                }
                              >
                                Reset MFA
                              </Button>
                              <Button variant="ghost" className="text-red-700 dark:text-red-400" aria-label={`Delete ${u.username}`} onClick={() => setDialog({ kind: "delete", user: u })}>
                                Delete
                              </Button>
                            </>
                          )}
                        </div>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </Table>
        )}
      </Card>

      <Dialog open={dialog.kind === "create"} title="New user" onClose={close}>
        <CreateUserForm actor={actor} onDone={(u) => done(`User ${u.username} created.`)} />
      </Dialog>
      <Dialog open={dialog.kind === "edit"} title="Edit user" onClose={close}>
        {dialog.kind === "edit" && <EditUserForm actor={actor} user={dialog.user} self={dialog.user.id === session.user.id} onDone={(u) => done(`User ${u.username} saved.`)} />}
      </Dialog>
      <Dialog open={dialog.kind === "password"} title="Reset password" onClose={close}>
        {dialog.kind === "password" && <ResetPasswordForm user={dialog.user} onDone={() => done(`Password of ${dialog.user.username} reset.`)} />}
      </Dialog>
      <Dialog open={dialog.kind === "delete"} title="Delete user" onClose={close}>
        {dialog.kind === "delete" && <DeleteUserForm user={dialog.user} onDone={() => done(`User ${dialog.user.username} deleted.`)} />}
      </Dialog>
      {can("security.manage") && <MFAPolicyCard />}
    </>
  );
}

/** MFAPolicyCard lets the owner require a second factor per role (AT-F09-05). */
function MFAPolicyCard() {
  const { data, reload } = useData(() => api.get<{ required: Record<Role, boolean> }>("/auth/mfa-policy"), []);
  const [draft, setDraft] = useState<Record<Role, boolean> | null>(null);
  const [message, setMessage] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  if (!data) return null;
  const current = draft ?? data.required;
  const save = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await api.put("/auth/mfa-policy", { required: current });
      setMessage({ kind: "success", text: "The MFA policy was saved." });
      setDraft(null);
      await reload();
    } catch (err) {
      setMessage({ kind: "error", text: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Require a second factor" className="mt-4">
      <fieldset className="space-y-2">
        <legend className="mb-2 text-sm text-slate-600 dark:text-slate-400">
          Users of these roles must set up an authenticator app or a passkey before they can use Kernhaven. Removing a role is recorded as a downgrade.
        </legend>
        {message && <Alert kind={message.kind}>{message.text}</Alert>}
        <div className="flex flex-wrap gap-4">
          {ROLES.map((r) => (
            <label key={r} className="flex items-center gap-2 text-sm">
              <input type="checkbox" className="size-4" checked={!!current[r]} onChange={(e) => setDraft({ ...current, [r]: e.target.checked })} />
              {roleLabel(r)}
            </label>
          ))}
        </div>
        <Button busy={busy} disabled={!draft} onClick={save}>
          Save policy
        </Button>
      </fieldset>
    </Card>
  );
}
