/** Settings injected at container start through /config.js. Never secrets. */
export interface BowerRuntimeConfig {
  authMode?: string;
  apiBaseUrl?: string;
  entraTenantId?: string;
  entraClientId?: string;
  entraApiScope?: string;
  entraRedirectUri?: string;
}

declare global {
  interface Window {
    __BOWER_CONFIG__?: BowerRuntimeConfig;
  }
}

const runtime: BowerRuntimeConfig =
  (typeof window === "undefined" ? undefined : window.__BOWER_CONFIG__) ?? {};

function pick(runtimeValue: string | undefined, buildValue: string | undefined) {
  return runtimeValue && runtimeValue.trim().length > 0 ? runtimeValue.trim() : buildValue;
}

/** Runtime values win when set; otherwise build-time VITE_BOWER_* values apply. */
export const bowerConfig = {
  authMode: pick(runtime.authMode, import.meta.env.VITE_BOWER_AUTH_MODE) ?? "entra",
  apiBaseUrl: pick(runtime.apiBaseUrl, import.meta.env.VITE_BOWER_API_BASE_URL) ?? "",
  entraTenantId: pick(runtime.entraTenantId, import.meta.env.VITE_BOWER_ENTRA_TENANT_ID) ?? "",
  entraClientId: pick(runtime.entraClientId, import.meta.env.VITE_BOWER_ENTRA_CLIENT_ID) ?? "",
  entraApiScope: pick(runtime.entraApiScope, import.meta.env.VITE_BOWER_ENTRA_API_SCOPE) ?? "",
  entraRedirectUri: pick(runtime.entraRedirectUri, import.meta.env.VITE_BOWER_ENTRA_REDIRECT_URI)
};
