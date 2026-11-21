import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { useApi } from "../api";
import { CopyButton } from "../components/SourcePlanView";
import { Page, ResourceState } from "../components/ui";
import { useResource } from "../hooks/useResource";
import { DiffView } from "./PrivacyProfileVersionPanel";

interface PolicyTemplateItem {
  id: string;
  title: string;
  description: string;
  content: string;
}

interface PolicySuppressionForm {
  enabled: boolean;
  keyFields: string[];
  windowSeconds: number;
  allowPerWindow: number;
}

interface PolicyForm {
  id: string;
  name: string;
  version: string;
  owner: string;
  eventCategories: string[];
  eventTypes: string[];
  requiredFields: string[];
  atLeastOne: string[];
  recommendedFields: string[];
  action: string;
  minimumValueScore: number;
  neverSample: boolean;
  suppression: PolicySuppressionForm | null;
}

interface PolicyFormResult {
  form: PolicyForm;
  content: string;
  valid: boolean;
  errors: string[];
  policyHash: string | null;
  diff: {
    beforeHash: string;
    afterHash: string;
    semanticallyIdentical: boolean;
    changes: { change: string; detail: string }[];
  } | null;
  preview: {
    valid: boolean;
    beforeDecision: string;
    afterDecision: string;
    valueScore: number;
    redactedEventJson: string | null;
    findings: { detectorId: string; action: string; path: string }[];
  } | null;
}

const decisionOptions = [
  { value: "accept", label: "Accept — keep and deliver matching events" },
  { value: "redact-and-accept", label: "Redact and accept — require redaction before delivery" },
  { value: "aggregate", label: "Aggregate — summarise floods into window counts" },
  { value: "quarantine", label: "Quarantine — set aside for review instead of delivering" },
  { value: "reject", label: "Reject — drop matching events" }
];

export function PoliciesPage() {
  const api = useApi();
  const templates = useResource<PolicyTemplateItem[]>("/api/policies/templates");
  const [selectedTemplateId, setSelectedTemplateId] = useState("");
  const [baselineContent, setBaselineContent] = useState("");
  const [form, setForm] = useState<PolicyForm | null>(null);
  const [result, setResult] = useState<PolicyFormResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const first = templates.data?.[0];
    if (first && !selectedTemplateId) {
      setSelectedTemplateId(first.id);
      setBaselineContent(first.content);
    }
  }, [templates.data, selectedTemplateId]);

  useEffect(() => {
    if (!baselineContent) return;
    let active = true;
    setBusy(true);
    setError(null);
    api<PolicyFormResult>("/api/policies/form", {
      method: "POST",
      body: JSON.stringify({ content: baselineContent, form: null })
    })
      .then((loaded) => {
        if (active) {
          setForm(loaded.form);
          setResult(loaded);
        }
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : "Could not load policy.");
      })
      .finally(() => {
        if (active) setBusy(false);
      });
    return () => {
      active = false;
    };
  }, [api, baselineContent]);

  async function previewChanges() {
    if (!form || !baselineContent) return;
    setBusy(true);
    setError(null);
    try {
      const next = await api<PolicyFormResult>("/api/policies/form", {
        method: "POST",
        body: JSON.stringify({ content: baselineContent, form })
      });
      setResult(next);
      if (next.valid) {
        setForm(next.form);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy check failed.");
    } finally {
      setBusy(false);
    }
  }

  function updateAction(action: string) {
    if (!form) return;
    const isAggregate = action === "aggregate";
    setForm({
      ...form,
      action,
      neverSample: isAggregate ? false : form.neverSample,
      suppression: isAggregate
        ? {
            enabled: true,
            keyFields: form.suppression?.keyFields.length
              ? form.suppression.keyFields
              : ["application.name", "eventType", "source.ipAddress"],
            windowSeconds: form.suppression?.windowSeconds || 60,
            allowPerWindow: form.suppression?.allowPerWindow ?? 0
          }
        : form.suppression
    });
  }

  return (
    <Page
      title="Policy editor"
      description="Edit telemetry policy decisions and flood suppression rules with plain-language controls, redacted sample previews, and population diffs."
    >
      {error && (
        <div className="alert alert--danger" role="alert">
          {error}
        </div>
      )}

      <ResourceState loading={templates.loading} error={templates.error} data={templates.data}>
        {(items) => (
          <section className="sheet" aria-labelledby="policy-editor-heading">
            <div className="section-heading">
              <h2 id="policy-editor-heading">
                <ShieldCheck aria-hidden="true" /> Guided policy decision &amp; suppression editor
              </h2>
              <span>Validated with the collector&apos;s PolicyLoader</span>
            </div>
            <div className="sheet-body">
              <label htmlFor="policy-template-select">Start from policy template</label>
              <select
                id="policy-template-select"
                value={selectedTemplateId}
                onChange={(event) => {
                  const chosen = items.find((item) => item.id === event.target.value);
                  if (chosen) {
                    setSelectedTemplateId(chosen.id);
                    setBaselineContent(chosen.content);
                  }
                }}
              >
                {items.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.title}
                  </option>
                ))}
              </select>

              {form && (
                <form
                  className="parser-form section-gap"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void previewChanges();
                  }}
                >
                  <label htmlFor="policy-id">Policy ID</label>
                  <input
                    id="policy-id"
                    type="text"
                    required
                    value={form.id}
                    onChange={(event) => setForm({ ...form, id: event.target.value })}
                  />

                  <label htmlFor="policy-version">Version</label>
                  <input
                    id="policy-version"
                    type="text"
                    required
                    value={form.version}
                    onChange={(event) => setForm({ ...form, version: event.target.value })}
                  />

                  <label htmlFor="policy-event-types">Event types (comma-separated)</label>
                  <input
                    id="policy-event-types"
                    type="text"
                    required
                    value={form.eventTypes.join(", ")}
                    onChange={(event) =>
                      setForm({
                        ...form,
                        eventTypes: event.target.value
                          .split(",")
                          .map((value) => value.trim())
                          .filter(Boolean)
                      })
                    }
                  />

                  <label htmlFor="policy-action">Decision action</label>
                  <select
                    id="policy-action"
                    value={form.action}
                    onChange={(event) => updateAction(event.target.value)}
                  >
                    {decisionOptions.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>

                  <label htmlFor="policy-min-score">Minimum value score (0–100)</label>
                  <input
                    id="policy-min-score"
                    type="number"
                    min={0}
                    max={100}
                    value={form.minimumValueScore}
                    onChange={(event) =>
                      setForm({ ...form, minimumValueScore: Number(event.target.value) })
                    }
                  />

                  <label>
                    <input
                      type="checkbox"
                      checked={form.suppression?.enabled ?? false}
                      onChange={(event) =>
                        setForm({
                          ...form,
                          neverSample: event.target.checked ? false : form.neverSample,
                          suppression: {
                            enabled: event.target.checked,
                            keyFields: form.suppression?.keyFields ?? [
                              "application.name",
                              "eventType",
                              "source.ipAddress"
                            ],
                            windowSeconds: form.suppression?.windowSeconds ?? 60,
                            allowPerWindow: form.suppression?.allowPerWindow ?? 0
                          }
                        })
                      }
                    />{" "}
                    Enable flood suppression / aggregation window
                  </label>

                  {form.suppression?.enabled && (
                    <fieldset className="privacy-field-rule">
                      <legend>Suppression &amp; aggregation window</legend>
                      <label htmlFor="policy-key-fields">Group by fields (comma-separated, max 5)</label>
                      <input
                        id="policy-key-fields"
                        type="text"
                        value={form.suppression.keyFields.join(", ")}
                        onChange={(event) =>
                          setForm({
                            ...form,
                            suppression: {
                              ...form.suppression!,
                              keyFields: event.target.value
                                .split(",")
                                .map((value) => value.trim())
                                .filter(Boolean)
                            }
                          })
                        }
                      />
                      <label htmlFor="policy-window-seconds">Window length (seconds, 60–3600)</label>
                      <input
                        id="policy-window-seconds"
                        type="number"
                        min={60}
                        max={3600}
                        value={form.suppression.windowSeconds}
                        onChange={(event) =>
                          setForm({
                            ...form,
                            suppression: {
                              ...form.suppression!,
                              windowSeconds: Number(event.target.value)
                            }
                          })
                        }
                      />
                      <label htmlFor="policy-allow-per-window">
                        Allow individual events per window (0 = summary only)
                      </label>
                      <input
                        id="policy-allow-per-window"
                        type="number"
                        min={0}
                        max={1000}
                        value={form.suppression.allowPerWindow}
                        onChange={(event) =>
                          setForm({
                            ...form,
                            suppression: {
                              ...form.suppression!,
                              allowPerWindow: Number(event.target.value)
                            }
                          })
                        }
                      />
                    </fieldset>
                  )}

                  <div className="button-row">
                    <button className="button button--primary" type="submit" disabled={busy}>
                      {busy ? "Checking…" : "Preview & diff"}
                    </button>
                  </div>
                </form>
              )}

              {result && (
                <section className="section-gap" aria-label="Policy preview and diff">
                  {!result.valid && (
                    <div className="alert alert--danger" role="alert">
                      {result.errors.join(" ")}
                    </div>
                  )}

                  {result.preview && (
                    <div className="sheet-body">
                      <h3>Sample preview (post-redaction only)</h3>
                      <p>
                        Before decision: <code>{result.preview.beforeDecision}</code> → After decision:{" "}
                        <code>{result.preview.afterDecision}</code> (value score {result.preview.valueScore}).
                      </p>
                      {result.preview.redactedEventJson && (
                        <pre className="code-block" tabIndex={0} aria-label="Redacted sample event">
                          {JSON.stringify(JSON.parse(result.preview.redactedEventJson), null, 2)}
                        </pre>
                      )}
                    </div>
                  )}

                  {result.diff && (
                    <div className="sheet-body section-gap">
                      <h3>Population diff</h3>
                      <p>
                        Hash: <code>{result.diff.beforeHash.slice(0, 18)}</code> →{" "}
                        <code>{result.diff.afterHash.slice(0, 18)}</code>{" "}
                        {result.diff.semanticallyIdentical && "(identical semantics)"}
                      </p>
                      {result.diff.changes.length === 0 ? (
                        <p>No semantic policy changes yet.</p>
                      ) : (
                        <ul>
                          {result.diff.changes.map((entry, idx) => (
                            <li key={idx}>
                              <strong>{entry.change}:</strong> {entry.detail}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}

                  <div className="section-gap">
                    <h3>Generated YAML diff</h3>
                    <DiffView previous={baselineContent} next={result.content} />
                    <details className="section-gap">
                      <summary>Generated TelemetryPolicy YAML</summary>
                      <pre className="code-block" tabIndex={0}>
                        {result.content}
                      </pre>
                      <CopyButton label="Copy policy YAML" text={result.content} />
                    </details>
                  </div>
                </section>
              )}
            </div>
          </section>
        )}
      </ResourceState>
    </Page>
  );
}
