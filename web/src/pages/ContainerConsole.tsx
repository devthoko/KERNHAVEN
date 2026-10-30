import { useEffect, useRef, useState, type FormEvent } from "react";
import { Alert, Button, Card, SelectField, TextField } from "../components/ui";
import { api, errorMessage } from "../lib/api";

/** stripControl removes terminal escape sequences and carriage returns; the console has no TTY. */
export function stripControl(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "").replace(/\x1b[()][0-9A-Za-z]/g, "").replace(/\r(?!\n)/g, "").replace(/\r\n/g, "\n");
}

const MAX_OUTPUT = 200_000;

/** Console is a line-based shell in a container (AT-F02-07, ADR-0031). */
export function Console({ id, name }: { id: string; name: string }) {
  const [shell, setShell] = useState<"sh" | "bash">("sh");
  const [session, setSession] = useState<string | null>(null);
  const [output, setOutput] = useState("");
  const [ended, setEnded] = useState<string | null>(null);
  const [line, setLine] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const box = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (!session) return;
    const es = new EventSource(`/api/v1/consoles/${session}/stream`);
    es.addEventListener("output", (e) => {
      const { text } = JSON.parse((e as MessageEvent).data) as { text: string };
      setOutput((o) => (o + stripControl(text)).slice(-MAX_OUTPUT));
    });
    es.addEventListener("end", (e) => {
      const { exit_code, reason } = JSON.parse((e as MessageEvent).data) as { exit_code?: number; reason: string };
      setEnded(exit_code !== undefined && exit_code !== null ? `The shell ended with exit code ${exit_code} (${reason}).` : `The console ended (${reason}).`);
      es.close();
    });
    return () => es.close();
  }, [session]);

  useEffect(() => {
    if (box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [output]);

  const open = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.post<{ console: string }>(`/containers/${encodeURIComponent(id)}/console`, { shell });
      setOutput("");
      setEnded(null);
      setSession(r.console);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const send = async (e: FormEvent) => {
    e.preventDefault();
    if (!session) return;
    const text = line;
    setLine("");
    try {
      await api.post(`/consoles/${session}/input`, { text: text + "\n" });
    } catch (err) {
      setError(errorMessage(err));
    }
  };
  const close = async () => {
    if (session) await api.del(`/consoles/${session}`).catch(() => undefined);
  };

  return (
    <Card title="Console">
      <div className="space-y-3">
        <p className="text-xs text-slate-600 dark:text-slate-400">
          A shell inside {name}, as the container&apos;s user. Lines are sent when you press Enter; full-screen programs (editors, top) do not work. Opening and closing are recorded in the
          audit log, what you type is not.
        </p>
        {error && <Alert>{error}</Alert>}
        {!session || ended ? (
          <div className="flex flex-wrap items-end gap-3">
            <div className="w-36">
              <SelectField label="Shell" value={shell} onChange={(e) => setShell(e.target.value as "sh" | "bash")}>
                <option value="sh">sh</option>
                <option value="bash">bash</option>
              </SelectField>
            </div>
            <Button variant="secondary" busy={busy} onClick={open}>
              Open console
            </Button>
          </div>
        ) : null}
        {ended && <Alert kind="info">{ended}</Alert>}
        {session && (
          <>
            <pre
              ref={box}
              role="log"
              tabIndex={0}
              aria-label="Console output"
              className="h-72 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-100"
            >
              {output || "Connected. Type a command below."}
            </pre>
            {!ended && (
              <form onSubmit={send} className="flex items-end gap-2">
                <div className="flex-1">
                  <TextField label="Command" autoFocus autoComplete="off" autoCapitalize="none" spellCheck={false} value={line} onChange={(e) => setLine(e.target.value)} />
                </div>
                <Button type="submit" variant="secondary">
                  Send
                </Button>
                <Button variant="ghost" onClick={close}>
                  Close console
                </Button>
              </form>
            )}
          </>
        )}
      </div>
    </Card>
  );
}
