import { useState, type ChangeEvent, type FormEvent } from "react";
import { AuthShell } from "../components/AuthShell";
import { Alert, Button, TextField } from "../components/ui";
import { errorMessage } from "../lib/api";
import { useSession } from "../lib/session";

export function SetupPage() {
  const { completeSetup } = useSession();
  const [form, setForm] = useState({ token: "", username: "", display_name: "", password: "", confirm: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof form) => (e: ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });

  const mismatch = form.confirm !== "" && form.password !== form.confirm;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (form.password !== form.confirm) return;
    setBusy(true);
    setError(null);
    try {
      await completeSetup({ token: form.token.trim(), username: form.username.trim(), display_name: form.display_name.trim(), password: form.password });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell title="Set up Kernhaven" subtitle="Create the owner account. The setup token is in the service journal.">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {error && <Alert>{error}</Alert>}
        <TextField
          label="Setup token"
          name="token"
          autoComplete="off"
          spellCheck={false}
          required
          value={form.token}
          onChange={set("token")}
          hint="Run: journalctl -u kernhaven-core | grep setup_token"
          autoFocus
        />
        <TextField label="Username" name="username" autoComplete="username" autoCapitalize="none" spellCheck={false} required value={form.username} onChange={set("username")} hint="3–32 characters: lowercase letters, digits, . _ -" />
        <TextField label="Display name (optional)" name="display_name" autoComplete="name" value={form.display_name} onChange={set("display_name")} />
        <TextField label="Password" name="password" type="password" autoComplete="new-password" required value={form.password} onChange={set("password")} hint="At least 12 characters. A passphrase of several words works well." />
        <TextField label="Confirm password" name="confirm" type="password" autoComplete="new-password" required value={form.confirm} onChange={set("confirm")} error={mismatch ? "The passwords do not match." : undefined} />
        <Button type="submit" className="w-full" busy={busy} disabled={!form.token || !form.username || !form.password || form.password !== form.confirm}>
          Create owner account
        </Button>
      </form>
    </AuthShell>
  );
}
