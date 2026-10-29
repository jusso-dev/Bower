import { useCallback, useEffect, useState } from "react";
import { useApi } from "../api";
import { bowerConfig } from "../runtimeConfig";
import type { Access } from "../types";

const authorRoles = ["Bower.Operator", "Bower.Approver", "Bower.Administrator"];
function preferenceKey(access: Access) {
  return `bower-console-view:${encodeURIComponent(bowerConfig.entraTenantId || "development")}:${encodeURIComponent(access.objectId)}`;
}

/** A display preference only. Roles and mutation permissions always come from the API. */
export function useConsoleView(authenticated: boolean) {
  const api = useApi();
  const [access, setAccess] = useState<Access | null>(null);
  const [detailed, setDetailed] = useState(false);
  const [loading, setLoading] = useState(authenticated);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    if (!authenticated) {
      setAccess(null);
      setDetailed(false);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(false);
    setAccess(null);
    setDetailed(false);
    api<Access>("/api/access/me").then(current => {
      if (!active) return;
      if (!current.objectId || !Array.isArray(current.roles)) throw new Error("Invalid access response");
      let saved: string | null = null;
      try { saved = localStorage.getItem(preferenceKey(current)); } catch { /* Storage can be disabled. */ }
      setAccess(current);
      setDetailed(saved === "detailed" || (saved !== "simple" && current.roles.some(role => authorRoles.includes(role))));
    }).catch(() => {
      if (active) { setAccess(null); setDetailed(false); setError(true); }
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [api, authenticated, retry]);

  const toggle = useCallback(() => {
    if (!access) return;
    const next = !detailed;
    setDetailed(next);
    try { localStorage.setItem(preferenceKey(access), next ? "detailed" : "simple"); } catch { /* Session-only preference remains usable. */ }
  }, [access, detailed]);

  return { access, detailed, loading, error, toggle, retry: () => setRetry(value => value + 1) };
}
