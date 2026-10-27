import { useCallback, useEffect, useRef, useState } from "react";
import { errorMessage } from "./api";

/**
 * useData loads data with fetcher and reloads when deps change. With
 * refreshMs it polls while shouldPoll(data) is true (live job progress).
 */
export function useData<T>(
  fetcher: () => Promise<T>,
  deps: unknown[],
  opts: { refreshMs?: number; shouldPoll?: (data: T) => boolean } = {},
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

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setLoading(true);
    const tick = async () => {
      const d = await reload();
      if (cancelled || !opts.refreshMs) return;
      if (d !== null && opts.shouldPoll && !opts.shouldPoll(d)) return;
      timer = setTimeout(tick, opts.refreshMs);
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
