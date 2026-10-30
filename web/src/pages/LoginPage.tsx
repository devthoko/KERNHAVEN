import { useState, type FormEvent } from "react";
import { AuthShell } from "../components/AuthShell";
import { Alert, Button, TextField, link } from "../components/ui";
import { ApiError, errorMessage } from "../lib/api";
import { useRouter } from "../lib/router";
import { useSession, type MFAChallenge } from "../lib/session";
import { passkeysSupported } from "../lib/webauthn";

function message(err: unknown): string {
  if (err instanceof ApiError && err.code === "rate_limited") return "Too many attempts. Wait a minute and try again.";
  if (err instanceof ApiError && err.code === "challenge_expired") return "The sign-in took too long. Start again.";
  if (err instanceof DOMException) return "The passkey was not used. Try again or use another method.";
  return errorMessage(err);
}

export function LoginPage({ expired }: { expired: boolean }) {
  const { login, completeMFA, mfaWithPasskey, loginWithPasskey } = useSession();
  const { search, navigate } = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState<MFAChallenge | null>(null);
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const done = () => {
    const next = search.get("next");
    // Only same-site relative paths are followed (no open redirect).
    navigate(next && next.startsWith("/") && !next.startsWith("//") ? next : "/", { replace: true });
  };
  const run = async (f: () => Promise<boolean>) => {
    setBusy(true);
    setError(null);
    try {
      if (await f()) done();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  const submitPassword = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      try {
        const c = await login(username.trim(), password);
        if (c) {
          setChallenge(c);
          setUseRecovery(!c.methods.includes("totp") && !c.methods.includes("passkey"));
          return false;
        }
        return true;
      } finally {
        setPassword("");
      }
    });
  };
  const submitCode = (e: FormEvent) => {
    e.preventDefault();
    if (!challenge) return;
    void run(async () => {
      await completeMFA(challenge.token, useRecovery ? { recovery_code: code } : { code });
      return true;
    }).finally(() => setCode(""));
  };

  if (challenge) {
    const hasTOTP = challenge.methods.includes("totp");
    const hasPasskey = challenge.methods.includes("passkey");
    const hasRecovery = challenge.methods.includes("recovery_code");
    return (
      <AuthShell title="Confirm it is you" subtitle="Your account is protected with a second factor.">
        <div className="space-y-4">
          {error && <Alert>{error}</Alert>}
          {hasPasskey && passkeysSupported() && (
            <Button className="w-full" busy={busy} onClick={() => run(async () => (await mfaWithPasskey(challenge.token), true))}>
              Use a passkey
            </Button>
          )}
          {(hasTOTP || hasRecovery) && (
            <form onSubmit={submitCode} className="space-y-4" noValidate>
              {useRecovery ? (
                <TextField label="Recovery code" autoComplete="off" autoCapitalize="characters" spellCheck={false} value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
              ) : (
                <TextField label="Code from your authenticator app" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} autoFocus />
              )}
              <Button type="submit" variant={hasPasskey ? "secondary" : "primary"} className="w-full" busy={busy} disabled={!code}>
                Continue
              </Button>
              {hasTOTP && hasRecovery && (
                <button type="button" className={`text-sm ${link}`} onClick={() => (setUseRecovery(!useRecovery), setCode(""))}>
                  {useRecovery ? "Use the authenticator app instead" : "Use a recovery code instead"}
                </button>
              )}
            </form>
          )}
          <Button variant="ghost" className="w-full" onClick={() => (setChallenge(null), setError(null))}>
            Start again
          </Button>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Sign in" subtitle="Manage your server securely.">
      <form onSubmit={submitPassword} className="space-y-4" noValidate>
        {expired && <Alert kind="info">Your session has ended. Please sign in again.</Alert>}
        {error && <Alert>{error}</Alert>}
        <TextField label="Username" name="username" autoComplete="username webauthn" autoCapitalize="none" spellCheck={false} required value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        <TextField label="Password" name="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        <Button type="submit" className="w-full" busy={busy} disabled={!username || !password}>
          Sign in
        </Button>
      </form>
      {passkeysSupported() && (
        <div className="mt-4">
          <Button variant="secondary" className="w-full" busy={busy} onClick={() => run(async () => (await loginWithPasskey(), true))}>
            Sign in with a passkey
          </Button>
        </div>
      )}
    </AuthShell>
  );
}
