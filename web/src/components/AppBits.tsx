import { useId } from "react";
import type { AppField, Disclosure, ServiceDisclosure } from "../lib/types";
import { Alert, Badge, SelectField, TextField } from "./ui";

function List({ label, items }: { label: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-600 dark:text-slate-400">{label}</dt>
      <dd>
        <ul className="mt-1 space-y-0.5">
          {items.map((i) => (
            <li key={i} className="break-all font-mono text-xs">
              {i}
            </li>
          ))}
        </ul>
      </dd>
    </div>
  );
}

function ServiceBox({ s }: { s: ServiceDisclosure }) {
  const flags: string[] = [];
  if (s.privileged) flags.push("privileged mode");
  if (s.host_network) flags.push("host network");
  return (
    <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="font-medium">{s.service}</span>
        <span className="min-w-0 break-all font-mono text-xs text-slate-600 dark:text-slate-400">{s.image}</span>
        {!s.image_pinned && <Badge tone="amber">Image not pinned</Badge>}
        {(s.user === "" || s.user === "0" || s.user === "root") && <Badge tone="amber">May run as root</Badge>}
      </div>
      <dl className="grid gap-2 sm:grid-cols-2">
        <List label="Published ports" items={s.ports} />
        <List label="Host folders" items={s.bind_mounts} />
        <List label="Volumes" items={s.volumes} />
        <List label="Extra capabilities" items={s.capabilities} />
        <List label="Devices" items={s.devices} />
        <List label="Special access" items={flags} />
      </dl>
      {s.exceptions.length > 0 && (
        <ul className="mt-2 space-y-1 text-sm">
          {s.exceptions.map((e) => (
            <li key={e.rule}>
              <Badge tone="red">Needs exception: {e.rule}</Badge> <span className="text-slate-700 dark:text-slate-300">{e.reason}</span>
            </li>
          ))}
        </ul>
      )}
      {s.warnings.length > 0 && (
        <ul className="mt-2 list-inside list-disc text-xs text-slate-600 dark:text-slate-400">
          {s.warnings.map((w, i) => (
            <li key={i}>{w.message}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** DisclosureView shows what an app may do, as Kernhaven computed it (AT-F04-04). */
export function DisclosureView({ disclosure }: { disclosure: Disclosure }) {
  return (
    <div className="space-y-3">
      {!disclosure.installable && (
        <Alert>
          This app cannot be installed on this host:
          <ul className="mt-1 list-inside list-disc">
            {disclosure.problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </Alert>
      )}
      {disclosure.installable && disclosure.needs_approval && (
        <Alert kind="warning">This app needs policy exceptions. Only an owner can approve them, and the approval is recorded in the audit log.</Alert>
      )}
      {disclosure.services.map((s) => (
        <ServiceBox key={s.service} s={s} />
      ))}
    </div>
  );
}

/** FieldInput renders one configuration field of a catalog app. */
export function FieldInput({ field, value, onChange }: { field: AppField; value: string; onChange: (v: string) => void }) {
  const id = useId();
  const hint = [field.description, field.generate ? "Leave empty to generate a random value." : "", field.type === "password" ? "Stored encrypted; it cannot be read back." : ""]
    .filter(Boolean)
    .join(" ");
  const label = field.required && !field.generate && !field.default ? `${field.label} (required)` : field.label;
  switch (field.type) {
    case "boolean":
      return (
        <div className="flex items-start gap-2">
          <input id={id} type="checkbox" className="mt-1 size-4" checked={value === "true"} onChange={(e) => onChange(e.target.checked ? "true" : "false")} />
          <label htmlFor={id} className="text-sm">
            <span className="font-medium">{field.label}</span>
            {field.description && <span className="block text-xs text-slate-600 dark:text-slate-400">{field.description}</span>}
          </label>
        </div>
      );
    case "select":
      return (
        <SelectField label={label} value={value} onChange={(e) => onChange(e.target.value)}>
          {(field.options ?? []).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </SelectField>
      );
    default:
      return (
        <TextField
          label={label}
          hint={hint || undefined}
          type={field.type === "password" ? "password" : field.type === "number" ? "number" : "text"}
          autoComplete={field.type === "password" ? "new-password" : "off"}
          min={field.min}
          max={field.max}
          value={value}
          placeholder={field.type === "password" && field.generate ? "generated" : undefined}
          onChange={(e) => onChange(e.target.value)}
        />
      );
  }
}

/** initialValues fills defaults; generated and secret fields start empty. */
export function initialValues(fields: AppField[]): Record<string, string> {
  const v: Record<string, string> = {};
  for (const f of fields) {
    if (f.type === "boolean") v[f.name] = f.default || "false";
    else if (f.type === "select") v[f.name] = f.default || f.options?.[0] || "";
    else v[f.name] = f.default ?? "";
  }
  return v;
}

/** changedValues sends only fields the user filled, so the server applies defaults and generators. */
export function changedValues(values: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(values)) if (v !== "") out[k] = v;
  return out;
}

