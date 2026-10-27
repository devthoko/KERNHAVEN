import { useState, type FormEvent } from "react";
import { AuthShell } from "../components/AuthShell";
import { Alert, Button, TextField } from "../components/ui";
import { ApiError, errorMessage } from "../lib/api";
import { useRouter } from "../lib/router";
import { useSession } from "../lib/session";

export function LoginPage({ expired }: { expired: boolean }) {
  const { login } = useSession();
  const { search, navigate } = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
      const next = search.get("next");
      // Only same-site relative paths are followed (no open redirect).
      navigate(next && next.startsWith("/") && !next.startsWith("//") ? next : "/", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError && err.code === "rate_limited" ? "Too many attempts. Wait a minute and try again." : errorMessage(err));
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell title="Sign in" subtitle="Manage your server securely.">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {expired && <Alert kind="info">Your session has ended. Please sign in again.</Alert>}
        {error && <Alert>{error}</Alert>}
        <TextField label="Username" name="username" autoComplete="username" autoCapitalize="none" spellCheck={false} required value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        <TextField label="Password" name="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        <Button type="submit" className="w-full" busy={busy} disabled={!username || !password}>
          Sign in
        </Button>
      </form>
    </AuthShell>
  );
}
