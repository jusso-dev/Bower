/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_BOWER_AUTH_MODE?: "development" | "entra";
  readonly VITE_BOWER_API_BASE_URL?: string;
  readonly VITE_BOWER_ENTRA_TENANT_ID?: string;
  readonly VITE_BOWER_ENTRA_CLIENT_ID?: string;
  readonly VITE_BOWER_ENTRA_API_SCOPE?: string;
  readonly VITE_BOWER_ENTRA_REDIRECT_URI?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
