import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { api, errorMessage } from "../lib/api";
import { useSession } from "../lib/session";
import type { StackEvaluation, StackException, StackVariable } from "../lib/types";
import { Alert, Badge, Button, Card, TextField } from "./ui";

export interface VariableRow {
  name: string;
  value: string;
  secret: boolean;
  stored: boolean; // a stored secret whose value is not shown
}

export function toRows(vars: StackVariable[]): VariableRow[] {
  return vars.map((v) => ({ name: v.name, value: v.value ?? "", secret: v.secret, stored: v.secret }));
}

/** Request form: a stored secret without a new value is sent without value (kept). */
export function toInput(rows: VariableRow[]) {
  return rows
    .filter((r) => r.name.trim())
    .map((r) => (r.secret && r.stored && r.value === "" ? { name: r.name.trim(), secret: true } : { name: r.name.trim(), value: r.value, secret: r.secret }));
}

interface Props {
  stackName: string;
  compose: string;
  onCompose: (v: string) => void;
  variables: VariableRow[];
  onVariables: (v: VariableRow[]) => void;
  exceptions: StackException[];
  onExceptions: (v: StackException[]) => void;
  onEvaluation?: (ev: StackEvaluation | null) => void;
}

export function StackEditor({ stackName, compose, onCompose, variables, onVariables, exceptions, onExceptions, onEvaluation }: Props) {
  const { can } = useSession();
  const area = useRef<HTMLTextAreaElement>(null);
  // After Escape, Tab leaves the editor (no keyboard trap, WCAG 2.1.2).
  const released = useRef(false);
  const [cursor, setCursor] = useState({ line: 1, col: 1 });
  const [evaluation, setEvaluation] = useState<StackEvaluation | null>(null);
  const [url, setUrl] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);

  useEffect(() => {
    if (!stackName || !compose.trim()) {
      setEvaluation(null);
      onEvaluation?.(null);
      return;
    }
    const t = setTimeout(async () => {
      try {
        const ev = await api.post<StackEvaluation>("/stacks/validate", { name: stackName, compose, variables: toInput(variables), exceptions });
        setEvaluation(ev);
        onEvaluation?.(ev);
      } catch {
        setEvaluation(null);
        onEvaluation?.(null);
      }
    }, 400);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stackName, compose, variables, exceptions]);

  const updateCursor = () => {
    const el = area.current;
    if (!el) return;
    const before = el.value.slice(0, el.selectionStart);
    const lines = before.split("\n");
    setCursor({ line: lines.length, col: (lines[lines.length - 1]?.length ?? 0) + 1 });
  };

  const goToLine = (line: number) => {
    const el = area.current;
    if (!el || line < 1) return;
    const lines = el.value.split("\n");
    const start = lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0);
    el.focus();
    el.setSelectionRange(start, start + (lines[line - 1]?.length ?? 0));
    updateCursor();
  };

  const upload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 256 * 1024) {
      setImportError("The file is larger than 256 KiB.");
      return;
    }
    onCompose(await file.text());
    setImportError(null);
    e.target.value = "";
  };

  const importUrl = async () => {
    setImporting(true);
    setImportError(null);
    try {
      const res = await api.post<{ compose: string }>("/stacks/import-url", { url: url.trim() });
      onCompose(res.compose);
      setUrl("");
    } catch (err) {
      setImportError(errorMessage(err));
    } finally {
      setImporting(false);
    }
  };

  const setVar = (i: number, patch: Partial<VariableRow>) => onVariables(variables.map((v, j) => (j === i ? { ...v, ...patch } : v)));
  const approved = (service: string, rule: string) => exceptions.find((x) => x.service === service && x.rule === rule);
  const setException = (service: string, rule: string, on: boolean, reason = "") =>
    onExceptions(on ? [...exceptions.filter((x) => !(x.service === service && x.rule === rule)), { service, rule, reason }] : exceptions.filter((x) => !(x.service === service && x.rule === rule)));

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="space-y-4 lg:col-span-2">
        <Card title="Compose file">
          <div className="mb-3 grid gap-3 sm:grid-cols-[1fr_auto] sm:items-end">
            <TextField label="Import from a public HTTPS URL" placeholder="https://…/compose.yaml" value={url} onChange={(e) => setUrl(e.target.value)} />
            <Button variant="secondary" busy={importing} disabled={!url.trim()} onClick={importUrl}>
              Import
            </Button>
          </div>
          <label className="mb-3 block text-sm">
            <span className="font-medium">or upload a file </span>
            <input type="file" accept=".yml,.yaml,text/yaml,text/plain" className="mt-1 block text-sm" onChange={upload} />
          </label>
          {importError && (
            <div className="mb-3">
              <Alert>{importError}</Alert>
            </div>
          )}
          <label htmlFor="compose-editor" className="block text-sm font-medium">
            compose.yaml
          </label>
          <textarea
            id="compose-editor"
            ref={area}
            rows={22}
            spellCheck={false}
            wrap="off"
            value={compose}
            onChange={(e) => onCompose(e.target.value)}
            onKeyUp={updateCursor}
            onClick={updateCursor}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                released.current = true;
                return;
              }
              if (e.key === "Tab" && released.current) {
                released.current = false;
                return;
              }
              if (e.key === "Tab" && !e.shiftKey) {
                // Two spaces instead of leaving the field; Escape then Tab leaves.
                e.preventDefault();
                const el = e.currentTarget;
                const s = el.selectionStart;
                onCompose(el.value.slice(0, s) + "  " + el.value.slice(el.selectionEnd));
                requestAnimationFrame(() => el.setSelectionRange(s + 2, s + 2));
              }
            }}
            className="mt-1 block w-full overflow-auto rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs leading-5 text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
          />
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
            Line {cursor.line}, column {cursor.col} · Tab inserts two spaces; press Escape, then Tab to leave the editor.
          </p>
        </Card>
        <Card title="Variables">
          <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">
            Use them as <code>${"{NAME}"}</code> in the file. All values are encrypted; secret values are never shown again.
          </p>
          <div className="space-y-2">
            {variables.map((v, i) => (
              <div key={i} className="grid gap-2 sm:grid-cols-[1fr_1.5fr_auto_auto] sm:items-end">
                <TextField label="Name" value={v.name} onChange={(e) => setVar(i, { name: e.target.value })} />
                <TextField
                  label="Value"
                  type={v.secret ? "password" : "text"}
                  autoComplete="off"
                  placeholder={v.secret && v.stored ? "stored (leave empty to keep)" : ""}
                  value={v.value}
                  onChange={(e) => setVar(i, { value: e.target.value })}
                />
                <label className="flex items-center gap-2 pb-2 text-sm">
                  <input type="checkbox" className="size-4" checked={v.secret} disabled={v.stored} onChange={(e) => setVar(i, { secret: e.target.checked })} />
                  Secret
                </label>
                <Button variant="ghost" aria-label={`Remove variable ${v.name || i + 1}`} onClick={() => onVariables(variables.filter((_, j) => j !== i))}>
                  Remove
                </Button>
              </div>
            ))}
          </div>
          <Button variant="secondary" className="mt-3" onClick={() => onVariables([...variables, { name: "", value: "", secret: false, stored: false }])}>
            Add variable
          </Button>
        </Card>
      </div>

      <Card title="Check">
        <div aria-live="polite" className="space-y-3 text-sm">
          {!evaluation && <p className="text-slate-600 dark:text-slate-400">Enter a Compose file to check it.</p>}
          {evaluation && evaluation.errors.length > 0 && (
            <ul className="space-y-2">
              {evaluation.errors.map((e, i) => (
                <li key={i}>
                  <button type="button" className="text-left text-red-800 underline dark:text-red-300" onClick={() => goToLine(e.line)}>
                    {e.line > 0 ? `Line ${e.line}: ` : ""}
                    {e.path}: {e.message}
                  </button>
                </li>
              ))}
            </ul>
          )}
          {evaluation?.valid && evaluation.deployable && <Alert kind="success">Valid and allowed by the container policy.</Alert>}
          {evaluation?.services.map((s) => (
            <div key={s.service} className="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
              <p className="font-medium">
                {s.service} <span className="font-normal text-slate-600 dark:text-slate-400">· {s.image}</span>
              </p>
              {s.violations.map((v) => {
                const ex = approved(s.service, v.rule);
                return (
                  <div key={v.rule} className="mt-2 rounded border border-red-300 p-2 dark:border-red-800">
                    <p className="font-medium text-red-800 dark:text-red-300">Violation: {v.rule}</p>
                    <p>{v.message}</p>
                    {!v.exemptible && <p className="font-medium">This can never be allowed.</p>}
                    {v.exemptible && (can("policy.exceptions") || ex) && (
                      <div className="mt-2 space-y-2">
                        <label className="flex items-center gap-2">
                          <input type="checkbox" className="size-4" checked={!!ex} disabled={!can("policy.exceptions")} onChange={(e) => setException(s.service, v.rule, e.target.checked)} />
                          Approve an exception (audited)
                        </label>
                        {ex && <TextField label="Reason (at least 10 characters)" value={ex.reason} disabled={!can("policy.exceptions")} onChange={(e) => setException(s.service, v.rule, true, e.target.value)} />}
                      </div>
                    )}
                    {v.exemptible && !can("policy.exceptions") && !ex && <p className="mt-1 text-xs">Only an owner can approve an exception.</p>}
                  </div>
                );
              })}
              {s.warnings.map((w) => (
                <p key={w.rule + w.message} className="mt-1 flex gap-2">
                  <Badge tone="amber">Warning</Badge>
                  <span>{w.message}</span>
                </p>
              ))}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
