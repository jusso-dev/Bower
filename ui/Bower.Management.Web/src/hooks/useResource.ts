import { useCallback, useEffect, useState } from "react";
import { useApi } from "../api";

export function useResource<T>(path: string, refresh = 0) {
  const api = useApi();
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api<T>(path));
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unknown request failure.");
    } finally {
      setLoading(false);
    }
  }, [api, path]);

  const [refreshError, setRefreshError] = useState<string | null>(null);

  /**
   * Refetches without the loading state, so the current view stays in place (polling). A
   * failure keeps the last good data and sets `refreshError`; resolves true on success.
   */
  const revalidate = useCallback(async () => {
    try {
      setData(await api<T>(path));
      setRefreshError(null);
      return true;
    } catch (loadError) {
      setRefreshError(loadError instanceof Error ? loadError.message : "Unknown request failure.");
      return false;
    }
  }, [api, path]);

  useEffect(() => {
    void load();
  }, [load, refresh]);

  return { data, loading, error, refreshError, reload: load, revalidate };
}
