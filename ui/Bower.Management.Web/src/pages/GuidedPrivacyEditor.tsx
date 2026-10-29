import { useEffect, useRef, useState } from "react";
import { useApi } from "../api";
import { CopyButton } from "../components/SourcePlanView";
import type { PrivacyProfilePreview, PrivacyProfileValidation, PrivacyProfileVersionDetail } from "../types";
import { DiffView } from "./PrivacyProfileVersionPanel";

type Field = { path: string; action: string; maxLength: number | null };
type Form = { id: string; version: string; description: string; fields: Field[] };
type Result = { form: Form; content: string; validation: PrivacyProfileValidation; preview: PrivacyProfilePreview };

const actions = [
  ["replace", "Redact the value"], ["mask", "Hide part of the value"],
  ["hmac", "Replace with a keyed identifier (HMAC)"], ["truncate", "Shorten the value"],
  ["remove", "Remove the field"], ["allow", "Keep the value"],
  ["alertonly", "Report a finding, keep the value"], ["sha256", "Replace with an unkeyed hash"],
  ["encrypt", "Encrypt using the collector's key"]
];

export function GuidedPrivacyEditor({ initialContent, basedOn, onCancel, onSubmitted }: {
  initialContent: string;
  basedOn: string | null;
  onCancel: () => void;
  onSubmitted: (detail: PrivacyProfileVersionDetail) => void;
}) {
  const api = useApi();
  const [form, setForm] = useState<Form | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"load" | "check" | "submit" | null>("load");
  const [retry, setRetry] = useState(0);
  const [summary, setSummary] = useState("");
  const revision = useRef(0);

  useEffect(() => {
    let active = true;
    setBusy("load");
    setError(null);
    api<Result>("/api/privacy-profiles/form", {
      method: "POST", body: JSON.stringify({ content: initialContent, form: null })
    }).then((loaded) => {
      if (active) setForm(loaded.form);
    }).catch(() => {
      if (active) setError("The profile could not be opened. Retry, or use the YAML editor to correct it.");
    }).finally(() => { if (active) setBusy(null); });
    return () => { active = false; };
  }, [api, initialContent, retry]);

  function change(next: Form) {
    revision.current++;
    setForm(next);
    setResult(null);
    setError(null);
  }

  async function check() {
    const checked = revision.current;
    setBusy("check");
    setError(null);
    try {
      const next = await api<Result>("/api/privacy-profiles/form", {
        method: "POST", body: JSON.stringify({ content: initialContent, form })
      });
      if (checked === revision.current) setResult(next);
    } catch (failure) {
      if (checked === revision.current) setError(failure instanceof Error ? failure.message : "The settings could not be checked.");
    } finally { setBusy(null); }
  }

  async function submit() {
    if (!result?.validation.valid || !result.preview.valid || !summary.trim()) return;
    setBusy("submit");
    setError(null);
    try {
      const detail = await api<PrivacyProfileVersionDetail>("/api/privacy-profiles", {
        method: "POST", body: JSON.stringify({ content: result.content, changeSummary: summary.trim() })
      });
      onSubmitted(detail);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "The version could not be submitted.");
    } finally { setBusy(null); }
  }

  return <section className="sheet section-gap guided-privacy-editor" aria-labelledby="guided-privacy-title">
    <div className="section-heading"><h2 id="guided-privacy-title">Choose what to protect</h2><span>{basedOn ?? "New privacy profile"}</span></div>
    <div className="sheet-body">
      <p>Choose an action for each field. Existing detector settings and advanced rules are preserved. Another person must approve the new version before it can be assigned.</p>
      {error && <div className="alert alert--danger" role="alert">{error}</div>}
      {busy === "load" && <p role="status">Opening profile…</p>}
      {!form && busy !== "load" && <button className="button button--secondary" type="button" onClick={() => setRetry(value => value + 1)}>Retry opening profile</button>}
      {form && <form className="parser-form" onSubmit={event => { event.preventDefault(); void check(); }}>
        <label htmlFor="privacy-form-id">Profile name</label>
        <input id="privacy-form-id" type="text" required maxLength={128} value={form.id} disabled={busy === "submit"} onChange={event => change({ ...form, id: event.target.value })} />
        <label htmlFor="privacy-form-version">New version</label>
        <input id="privacy-form-version" type="text" required maxLength={64} value={form.version} aria-describedby="privacy-form-version-help" disabled={busy === "submit"} onChange={event => change({ ...form, version: event.target.value })} />
        <p className="form-help" id="privacy-form-version-help">Use three numbers, such as 1.0.1. The version must be higher than every version already submitted for this profile.</p>
        <label htmlFor="privacy-form-description">What this profile protects</label>
        <textarea id="privacy-form-description" maxLength={2000} value={form.description} disabled={busy === "submit"} onChange={event => change({ ...form, description: event.target.value })} />
        <h3>Field actions</h3>
        <p className="form-help">Use a field path such as actor.username or attributes.message. Rules run in this order. No rules here means the profile's existing detector settings still apply.</p>
        {form.fields.map((field, index) => {
          function update(next: Field) { if (form) change({ ...form, fields: form.fields.map((item, i) => i === index ? next : item) }); }
          return <fieldset className="privacy-field-rule" key={index} disabled={busy === "submit"}>
            <legend>Field {index + 1}</legend>
            <label htmlFor={`privacy-path-${index}`}>Field path</label>
            <input id={`privacy-path-${index}`} type="text" required maxLength={256} value={field.path} onChange={event => update({ ...field, path: event.target.value })} />
            <label htmlFor={`privacy-action-${index}`}>How to protect it</label>
            <select id={`privacy-action-${index}`} value={field.action} onChange={event => update({ ...field, action: event.target.value, maxLength: event.target.value === "truncate" ? (field.maxLength ?? 64) : null })}>
              {actions.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
            {field.action === "truncate" && <><label htmlFor={`privacy-length-${index}`}>Maximum characters</label><input id={`privacy-length-${index}`} type="number" required min={1} max={65536} value={field.maxLength ?? ""} onChange={event => update({ ...field, maxLength: event.target.value === "" ? null : Number(event.target.value) })} /></>}
            {field.action === "hmac" && <p className="form-help">The collector needs its own HMAC key. The example uses a temporary key, so its identifiers differ from production.</p>}
            {["allow", "alertonly", "sha256", "truncate"].includes(field.action) && <p className="form-help">This action can retain identifying information. Review the reason and intended field carefully.</p>}
            <button className="button button--secondary" type="button" onClick={() => change({ ...form, fields: form.fields.filter((_, i) => i !== index) })}>Remove field {index + 1}</button>
          </fieldset>;
        })}
        <div className="button-row">
          <button className="button button--secondary" type="button" disabled={form.fields.length >= 128 || busy === "submit"} onClick={() => change({ ...form, fields: [...form.fields, { path: "", action: "replace", maxLength: null }] })}>Add a field</button>
          <button className="button button--primary" type="submit" disabled={busy !== null}>{busy === "check" ? "Checking…" : "Review changes"}</button>
        </div>
      </form>}
      {result && <section className="section-gap" aria-label="Review privacy changes">
        <h3>Review before submitting</h3>
        {!result.validation.valid && <div className="alert alert--danger" role="alert">{result.validation.errors.join(" ")}</div>}
        <p>The example is made up on the server. Only its protected result is shown. It does not measure live traffic or prove delivery. The preview always applies Bower's built-in protection, even if a profile permits values.</p>
        {result.preview.valid && result.preview.redacted ? <pre className="code-block" tabIndex={0} aria-label="Protected privacy example">{JSON.stringify(JSON.parse(result.preview.redacted), null, 2)}</pre> : <p role="alert">The example could not be protected. Submission is disabled.</p>}
        <h3>Configuration changes</h3>
        <DiffView previous={initialContent} next={result.content} />
        <details><summary>Generated YAML</summary><pre className="code-block" tabIndex={0}>{result.content}</pre><CopyButton label="Copy generated YAML" text={result.content} /></details>
        <form className="parser-form section-gap" onSubmit={event => { event.preventDefault(); void submit(); }}>
          <label htmlFor="privacy-guided-summary">Why this change is needed</label>
          <textarea id="privacy-guided-summary" required maxLength={500} value={summary} disabled={busy === "submit"} onChange={event => setSummary(event.target.value)} />
          <button className="button button--primary" type="submit" disabled={busy !== null || !result.validation.valid || !result.preview.valid || !summary.trim()}>{busy === "submit" ? "Submitting…" : "Ask another person to approve"}</button>
        </form>
      </section>}
      <div className="button-row section-gap"><button className="button button--secondary" type="button" disabled={busy === "submit"} onClick={onCancel}>Cancel</button></div>
    </div>
  </section>;
}
