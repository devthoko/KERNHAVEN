import { useCallback, useEffect, useRef, useState } from "react";
import { errorMessage } from "./api";
import { liveAvailable, subscribe, type LiveKind } from "./live";

/**
 * useData loads data with fetcher and reloads when deps change. With
 * refreshMs it polls while shouldPoll(data) is true (live job progress).
 * With live it reloads when the server reports a change of those kinds
 * (M6b) and polls only every 30 s as a safety net.
 */
export function useData<T>(
  fetcher: () => Promise<T>,
  deps: unknown[],
  opts: { refreshMs?: number; shouldPoll?: (data: T) => boolean; live?: LiveKind[] } = {},
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const reload = useCallback(async () => {
    try {
      const d = await fetcherRef.current();
      setData(d);
      setError(null);
      return d;
    } catch (err) {
      setError(errorMessage(err));
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const liveKey = (opts.live ?? []).join();
  useEffect(() => {
    if (!liveKey || !liveAvailable()) return;
    return subscribe(liveKey.split(",") as LiveKind[], () => void reload());
  }, [liveKey, reload]);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setLoading(true);
    const interval = opts.live?.length && liveAvailable() && opts.refreshMs ? Math.max(opts.refreshMs, 30000) : opts.refreshMs;
    const tick = async () => {
      const d = await reload();
      if (cancelled || !interval) return;
      if (d !== null && opts.shouldPoll && !opts.shouldPoll(d)) return;
      timer = setTimeout(tick, interval);
    };
    void tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload, setData };
}
