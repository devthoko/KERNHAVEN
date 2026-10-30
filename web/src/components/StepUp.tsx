import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, ApiError, errorMessage, setStepUpHandler } from "../lib/api";
import type { Ceremony, MFAStatus } from "../lib/types";
import { getPasskey, passkeysSupported } from "../lib/webauthn";
import { Alert, Button, Dialog, TextField, link } from "./ui";

/**
 * StepUpDialog confirms the user when an action needs a recent strong
 * authentication (AT-F09-04). api.ts calls it and repeats the request.
 */
export function StepUpDialog() {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<MFAStatus | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const resolve = useRef<((ok: boolean) => void) | null>(null);

  useEffect(() => {
    setStepUpHandler(
      () =>
        new Promise<boolean>((res) => {
          resolve.current = res;
          setPassword("");
          setCode("");
          setRecovery(false);
          setError(null);
          setStatus(null);
          setOpen(true);
          api.get<MFAStatus>("/auth/mfa").then(setStatus, () => setStatus(null));
        }),
    );
    return () => setStepUpHandler(null);
  }, []);

  const finish = (ok: boolean) => {
    setOpen(false);
    resolve.current?.(ok);
    resolve.current = null;
  };
  const run = async (f: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await f();
      finish(true);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? "That did not match. Try again." : err instanceof DOMException ? "The passkey was not used." : errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(() => api.post("/auth/step-up", { password, ...(needsCode ? (useRecovery ? { recovery_code: code } : { code }) : {}) }));
  };
  const withPasskey = () =>
    run(async () => {
      const c = await api.post<Ceremony>("/auth/step-up/passkey/begin");
      const credential = await getPasskey(c.options);
      await api.post("/auth/step-up/passkey/finish", { token: c.token, credential });
    });

  const hasPasskey = (status?.passkeys.length ?? 0) > 0 && passkeysSupported();
  // With any second factor the password alone is not enough; without TOTP the
  // second factor next to the password is a recovery code.
  const needsCode = !!status && (status.totp || status.passkeys.length > 0);
  const useRecovery = recovery || (!!status && !status.totp);
  return (
    <Dialog open={open} title="Confirm it is you" onClose={() => finish(false)}>
      <div className="space-y-4">
        <p className="text-sm">This action needs a fresh confirmation. It stays valid for 10 minutes.</p>
        {error && <Alert>{error}</Alert>}
        {hasPasskey && (
          <Button className="w-full" busy={busy} onClick={withPasskey}>
            Use a passkey
          </Button>
        )}
        {status && status.password_login && (
          <form className="space-y-3" onSubmit={submit}>
            <TextField label="Password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus={!hasPasskey} />
            {needsCode &&
              (useRecovery ? (
                <TextField label="Recovery code" autoComplete="off" spellCheck={false} value={code} onChange={(e) => setCode(e.target.value)} />
              ) : (
                <TextField label="Authenticator code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
              ))}
            {status.totp && status.recovery_codes_left > 0 && (
              <button type="button" className={`text-sm ${link}`} onClick={() => (setRecovery(!recovery), setCode(""))}>
                {recovery ? "Use the authenticator app" : "Use a recovery code"}
              </button>
            )}
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => finish(false)}>
                Cancel
              </Button>
              <Button type="submit" variant={hasPasskey ? "secondary" : "primary"} busy={busy} disabled={!password || (needsCode && !code)}>
                Confirm
              </Button>
            </div>
          </form>
        )}
        {status && !status.password_login && (
          <div className="flex justify-end">
            <Button variant="secondary" onClick={() => finish(false)}>
              Cancel
            </Button>
          </div>
        )}
      </div>
    </Dialog>
  );
}
