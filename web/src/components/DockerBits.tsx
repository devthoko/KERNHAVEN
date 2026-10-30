import { useState, type ReactNode } from "react";
import { Alert, Button, Dialog, StatusBadge, TextField } from "./ui";

export function StateBadge({ state }: { state: string }) {
  return <StatusBadge status={state} />;
}

/** AgentError explains why Docker data is missing instead of showing an empty page. */
export function AgentError({ message }: { message: string }) {
  return (
    <Alert kind="warning">
      {message} Check that kernhaven-agent and Docker are running (Dashboard → Platform).
    </Alert>
  );
}

/** ConfirmByName asks the user to type a name before a destructive action. */
export function ConfirmByName({
  open,
  title,
  name,
  children,
  action,
  onClose,
  onConfirm,
}: {
  open: boolean;
  title: string;
  name: string;
  children?: ReactNode;
  action: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
      setTyped("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} title={title} onClose={onClose}>
      <div className="space-y-4">
        {error && <Alert>{error}</Alert>}
        {children}
        <TextField label={`Type "${name}" to confirm`} autoCapitalize="none" spellCheck={false} value={typed} onChange={(e) => setTyped(e.target.value)} />
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="danger" busy={busy} disabled={typed !== name} onClick={run}>
            {action}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
