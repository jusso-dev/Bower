import { useCallback } from "react";
import { useAuth } from "./auth";

const baseUrl = import.meta.env.VITE_BOWER_API_BASE_URL ?? "";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number
  ) {
    super(message);
  }
}

export function useApi() {
  const { getAccessToken } = useAuth();

  return useCallback(
    async function request<T>(path: string, init?: RequestInit): Promise<T> {
      const token = await getAccessToken();
      const response = await fetch(`${baseUrl}${path}`, {
        ...init,
        headers: {
          Accept: "application/json",
          ...(init?.body ? { "Content-Type": "application/json" } : {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...init?.headers
        }
      });
      if (!response.ok) {
        let message = `Request failed with status ${response.status}.`;
        try {
          const body = (await response.json()) as { error?: string; title?: string };
          message = body.error ?? body.title ?? message;
        } catch {
          // The status is still useful when the response is not JSON.
        }
        throw new ApiError(message, response.status);
      }
      return (await response.json()) as T;
    },
    [getAccessToken]
  );
}
