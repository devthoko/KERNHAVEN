/**
 * live keeps one server-sent event stream (/api/v1/events, M6b) for the
 * whole page and calls subscribers when a kind of data changed. Without
 * EventSource (tests, old browsers) pages keep polling.
 */
export type LiveKind = "containers" | "jobs" | "alerts";

type Listener = () => void;

const listeners = new Map<LiveKind, Set<Listener>>();
let source: EventSource | null = null;

function count(): number {
  let n = 0;
  for (const set of listeners.values()) n += set.size;
  return n;
}

function open() {
  if (source || typeof EventSource === "undefined") return;
  const es = new EventSource("/api/v1/events");
  es.addEventListener("change", (e) => {
    try {
      const kind = (JSON.parse((e as MessageEvent).data) as { type: LiveKind }).type;
      for (const fn of listeners.get(kind) ?? []) fn();
    } catch {
      /* ignore malformed events */
    }
  });
  // The server ends each stream after a few minutes; EventSource reconnects
  // by itself, and the session is checked again.
  source = es;
}

/** liveAvailable reports whether changes are pushed (otherwise poll). */
export function liveAvailable(): boolean {
  return typeof EventSource !== "undefined";
}

/** subscribe calls fn whenever one of kinds changes; it returns the unsubscribe function. */
export function subscribe(kinds: LiveKind[], fn: Listener): () => void {
  for (const k of kinds) {
    if (!listeners.has(k)) listeners.set(k, new Set());
    listeners.get(k)!.add(fn);
  }
  open();
  return () => {
    for (const k of kinds) listeners.get(k)?.delete(fn);
    if (count() === 0 && source) {
      source.close();
      source = null;
    }
  };
}
