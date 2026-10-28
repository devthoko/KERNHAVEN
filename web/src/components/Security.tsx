import { useState } from "react";
import { api, errorMessage } from "../lib/api";
import { formatDateTime } from "../lib/format";
import { useSession } from "../lib/session";
import type { Ceremony, MFAStatus } from "../lib/types";
import { useData } from "../lib/useData";
import { createPasskey, passkeysSupported } from "../lib/webauthn";
import { Alert, Badge, Button, Card, TextField } from "./ui";

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  return (
    <div className="space-y-3">
      <Alert kind="warning">Save these recovery codes now, for example in your password manager. Each works once, and they are not shown again.</Alert>
      <ul aria-label="Recovery codes" className="grid grid-cols-2 gap-1 rounded bg-slate-100 p-3 font-mono text-sm sm:grid-cols-5 dark:bg-slate-800">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <Button variant="secondary" onClick={onDone}>
        I saved them
      </Button>
    </div>
  );
}

/** SecurityCard manages the user's sign-in methods (AT-F09-02, AT-F09-03). */
export function SecurityCard() {
  const { refresh } = useSession();
  const { data, error, reload } = useData(() => api.get<MFAStatus>("/auth/mfa"), []);
  const [totp, setTotp] = useState<{ secret: string; otpauth_url: string } | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [passkeyName, setPasskeyName] = useState("");
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (f: () => Promise<void>, success?: string) => {
    setBusy(true);
    setNotice(null);
    try {
      await f();
      if (success) setNotice({ kind: "success", text: success });
      await reload();
      await refresh();
    } catch (err) {
      setNotice({ kind: "error", text: err instanceof DOMException ? "The passkey was not created." : errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  if (error) return <Alert>{error}</Alert>;
  if (!data) return null;
  const factors = (data.totp ? 1 : 0) + data.passkeys.length;
  return (
    <Card title="Sign-in security">
      <div className="space-y-6">
        {notice && <Alert kind={notice.kind}>{notice.text}</Alert>}
        {data.required_by_policy && factors === 0 && <Alert kind="warning">Your role requires a second factor. Set up an authenticator app or a passkey to continue.</Alert>}
        {codes && <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />}

        <section aria-labelledby="totp-heading" className="space-y-2">
          <h3 id="totp-heading" className="text-sm font-semibold">
            Authenticator app {data.totp && <Badge tone="green">on</Badge>}
          </h3>
          {!data.totp && !totp && (
            <Button variant="secondary" busy={busy} onClick={() => run(async () => setTotp(await api.post("/auth/mfa/totp")))}>
              Set up an authenticator app
            </Button>
          )}
          {totp && (
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                void run(async () => {
                  const res = await api.post<{ recovery_codes: string[] }>("/auth/mfa/totp/confirm", { code });
                  setTotp(null);
                  setCode("");
                  setCodes(res.recovery_codes);
                }, "The authenticator app is set up.");
              }}
            >
              <p className="text-sm">Add Kernhaven to your authenticator app with this key, then enter the code it shows.</p>
              <p className="break-all rounded bg-slate-100 p-2 font-mono text-sm dark:bg-slate-800" aria-label="Setup key">
                {totp.secret.replace(/(.{4})/g, "$1 ").trim()}
              </p>
              <p className="text-xs">
                <a href={totp.otpauth_url} className="text-brand-700 underline dark:text-brand-500">
                  Open in an authenticator app on this device
                </a>
              </p>
              <TextField label="Code from the app" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
              <div className="flex gap-2">
                <Button type="submit" busy={busy} disabled={code.length !== 6}>
                  Turn on
                </Button>
                <Button variant="ghost" onClick={() => setTotp(null)}>
                  Cancel
                </Button>
              </div>
            </form>
          )}
          {data.totp && (
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span>{data.recovery_codes_left} recovery codes left.</span>
              <Button variant="secondary" busy={busy} onClick={() => run(async () => setCodes((await api.post<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes")).recovery_codes))}>
                New recovery codes
              </Button>
              <Button variant="ghost" className="text-red-700 dark:text-red-400" busy={busy} onClick={() => run(() => api.del("/auth/mfa/totp"), "The authenticator app was removed.")}>
                Remove authenticator app
              </Button>
            </div>
          )}
        </section>

        <section aria-labelledby="passkeys-heading" className="space-y-2">
          <h3 id="passkeys-heading" className="text-sm font-semibold">
            Passkeys
          </h3>
          {data.passkeys.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">No passkeys yet. A passkey signs you in with your device&apos;s fingerprint, face or PIN.</p>}
          <ul className="space-y-1">
            {data.passkeys.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-medium">{p.name}</span>
                <span className="text-slate-600 dark:text-slate-400">added {formatDateTime(p.created_at)}{p.last_used_at ? `, last used ${formatDateTime(p.last_used_at)}` : ""}</span>
                <Button variant="ghost" className="text-red-700 dark:text-red-400" busy={busy} onClick={() => run(() => api.del(`/auth/passkeys/${p.id}`), `${p.name} was removed.`)}>
                  Remove <span className="sr-only">{p.name}</span>
                </Button>
              </li>
            ))}
          </ul>
          {passkeysSupported() ? (
            <form
              className="flex flex-wrap items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void run(async () => {
                  const c = await api.post<Ceremony>("/auth/passkeys/begin");
                  const credential = await createPasskey(c.options);
                  await api.post("/auth/passkeys/finish", { token: c.token, name: passkeyName, credential });
                  setPasskeyName("");
                }, "The passkey was added.");
              }}
            >
              <div className="min-w-48 flex-1">
                <TextField label="Passkey name" placeholder="e.g. Laptop" maxLength={64} value={passkeyName} onChange={(e) => setPasskeyName(e.target.value)} />
              </div>
              <Button type="submit" variant="secondary" busy={busy}>
                Add a passkey
              </Button>
            </form>
          ) : (
            <p className="text-sm text-slate-600 dark:text-slate-400">This browser does not support passkeys.</p>
          )}
        </section>

        {data.passkeys.length > 0 && (
          <section aria-labelledby="password-heading" className="space-y-2">
            <h3 id="password-heading" className="text-sm font-semibold">
              Password sign-in {data.password_login ? <Badge>on</Badge> : <Badge tone="blue">off — passkeys only</Badge>}
            </h3>
            <Button variant="secondary" busy={busy} onClick={() => run(() => api.put("/auth/password-login", { enabled: !data.password_login }), data.password_login ? "Password sign-in is off." : "Password sign-in is on.")}>
              {data.password_login ? "Sign in with passkeys only" : "Allow password sign-in again"}
            </Button>
          </section>
        )}
      </div>
    </Card>
  );
}
