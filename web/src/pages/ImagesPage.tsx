import { useState, type FormEvent } from "react";
import { AgentError, ConfirmByName } from "../components/DockerBits";
import { Alert, Button, Card, PageHeader, Spinner, Table, TextField, td, th } from "../components/ui";
import { api, errorMessage } from "../lib/api";
import { formatBytes, formatDateTime } from "../lib/format";
import { Link } from "../lib/router";
import { useSession } from "../lib/session";
import type { ImageSummary } from "../lib/types";
import { useData } from "../lib/useData";

const imageName = (i: ImageSummary) => i.repo_tags[0] ?? i.repo_digests[0]?.split("@")[0] ?? i.id.replace("sha256:", "").slice(0, 12);

export function ImagesPage() {
  const { can } = useSession();
  const { data, error, loading, reload } = useData(() => api.get<{ images: ImageSummary[] }>("/images"), [], { refreshMs: 5000 });
  const [reference, setReference] = useState("");
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string; job?: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState<ImageSummary | null>(null);

  const pull = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const res = await api.post<{ job_id: number }>("/images/pull", { reference: reference.trim() });
      setNotice({ kind: "success", text: `Pulling ${reference.trim()}.`, job: res.job_id });
      setReference("");
    } catch (err) {
      setNotice({ kind: "error", text: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  const prune = async () => {
    setNotice(null);
    try {
      const res = await api.post<{ deleted: number; space_reclaimed: number }>("/images/prune");
      setNotice({ kind: "success", text: `Removed ${res.deleted} unused image layers, reclaimed ${formatBytes(res.space_reclaimed)}.` });
      await reload();
    } catch (err) {
      setNotice({ kind: "error", text: errorMessage(err) });
    }
  };

  return (
    <>
      <PageHeader
        title="Images"
        description="Container images on this host. Pulls run as background jobs and record the image digest."
        actions={can("containers.manage") ? <Button variant="secondary" onClick={prune}>Remove dangling images</Button> : undefined}
      />
      {notice && (
        <div className="mb-4">
          <Alert kind={notice.kind}>
            {notice.text}{" "}
            {notice.job && (
              <Link to={`/jobs/${notice.job}`} className="underline">
                Follow job #{notice.job}
              </Link>
            )}
          </Alert>
        </div>
      )}
      {can("containers.manage") && (
        <Card title="Pull an image" className="mb-4">
          <form onSubmit={pull} className="grid gap-3 sm:grid-cols-[1fr_auto] sm:items-end" noValidate>
            <TextField label="Image reference" placeholder="e.g. nginx:1.27 or ghcr.io/org/app:1.0" autoCapitalize="none" spellCheck={false} value={reference} onChange={(e) => setReference(e.target.value)} />
            <Button type="submit" busy={busy} disabled={!reference.trim()}>
              Pull
            </Button>
          </form>
        </Card>
      )}
      <Card>
        {loading && !data && <Spinner />}
        {error && <AgentError message={error} />}
        {data && data.images.length === 0 && <p className="text-sm text-slate-600 dark:text-slate-400">No images.</p>}
        {data && data.images.length > 0 && (
          <Table
            caption="Images"
            head={
              <tr>
                <th className={th}>Image</th>
                <th className={th}>Digest</th>
                <th className={th}>Size</th>
                <th className={th}>Used by</th>
                <th className={th}>Created</th>
                {can("containers.manage") && (
                  <th className={th}>
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            }
          >
            {data.images.map((i) => (
              <tr key={i.id}>
                <td className={td}>
                  <div className="font-medium">{imageName(i)}</div>
                  {i.repo_tags.length > 1 && <div className="text-xs text-slate-600 dark:text-slate-400">{i.repo_tags.slice(1).join(", ")}</div>}
                </td>
                <td className={`${td} font-mono text-xs`} title={i.repo_digests.join("\n")}>
                  {i.repo_digests[0]?.split("@")[1]?.slice(0, 19) ?? "local only"}
                </td>
                <td className={td}>{formatBytes(i.size)}</td>
                <td className={td}>{i.containers} container(s)</td>
                <td className={td}>{formatDateTime(new Date(i.created * 1000).toISOString())}</td>
                {can("containers.manage") && (
                  <td className={`${td} text-right`}>
                    <Button variant="ghost" className="text-red-700 dark:text-red-400" aria-label={`Remove ${imageName(i)}`} onClick={() => setRemoving(i)}>
                      Remove
                    </Button>
                  </td>
                )}
              </tr>
            ))}
          </Table>
        )}
      </Card>
      {removing && (
        <ConfirmByName
          open
          title="Remove image"
          name={imageName(removing)}
          action="Remove image"
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            await api.post("/images/remove", { reference: removing.repo_tags[0] ?? removing.id });
            setRemoving(null);
            await reload();
          }}
        >
          <p className="text-sm">Images used by containers cannot be removed.</p>
        </ConfirmByName>
      )}
    </>
  );
}
