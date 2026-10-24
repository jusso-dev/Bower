import { useCallback } from "react";
import { useAuth } from "./auth";
import { bowerConfig } from "./runtimeConfig";

const baseUrl = bowerConfig.apiBaseUrl;

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
          const body = (await response.json()) as {
            error?: string;
            title?: string;
            errors?: Record<string, unknown>;
          };
          message = body.error ?? validationMessages(body.errors) ?? body.title ?? message;
        } catch {
          // The status is still useful when the response is not JSON.
        }
        throw new ApiError(message, response.status);
      }
      // 202/204 responses (for example job triggers) carry no body.
      const text = await response.text();
      return (text ? JSON.parse(text) : undefined) as T;
    },
    [getAccessToken]
  );
}

/** Flattens ASP.NET validation problem details (`errors: { field: string[] }`) into one message. */
function validationMessages(errors: Record<string, unknown> | undefined): string | undefined {
  if (!errors || typeof errors !== "object") {
    return undefined;
  }
  const messages = Object.values(errors)
    .flatMap((value) => (Array.isArray(value) ? value : [value]))
    .filter((value): value is string => typeof value === "string" && value.length > 0);
  return messages.length ? messages.join(" ") : undefined;
}
