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

  useEffect(() => {
    void load();
  }, [load, refresh]);

  return { data, loading, error, reload: load };
}
