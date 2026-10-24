import { CheckCircle2, Eye, Send } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useApi } from "../api";
import type {
  PrivacyProfilePreview,
  PrivacyProfileValidation,
  PrivacyProfileVersionDetail
} from "../types";

/** Preview samples are bounded by the API at 64 KiB of JSON text. */
const maxSampleBytes = 64 * 1024;

export const starterProfile = `apiVersion: bower.security/v1
kind: PrivacyProfile
metadata:
  id: my-privacy-profile
  version: 1.0.0
  description: Describe what this privacy profile changes.
`;

const customDetectorExample = String.raw`customDetectors:
  - id: custom.employee-id
    description: Contoso employee numbers
    pattern: 'EMP-\d{6}'
    wholeWord: true
    action: mask
    tests:
      match: ["EMP-123456", "user EMP-000001 logged in"]
      noMatch: ["EMP-12345"]`;

/**
 * Authoring surface for a new privacy profile version. Content and samples live in
 * component state only: never in browser storage.
 */
export function PrivacyProfileEditor({
  initialContent,
  basedOn,
  onCancel,
  onSubmitted
}: {
  initialContent: string;
  basedOn: string | null;
  onCancel: () => void;
  onSubmitted: (detail: PrivacyProfileVersionDetail) => void;
}) {
  const api = useApi();
  const [content, setContent] = useState(initialContent);
  const [changeSummary, setChangeSummary] = useState("");
  const [sample, setSample] = useState("");
  const [validation, setValidation] = useState<PrivacyProfileValidation | null>(null);
  const [preview, setPreview] = useState<PrivacyProfilePreview | null>(null);
  const [busy, setBusy] = useState<"validate" | "preview" | "submit" | null>(null);
  const [error, setError] = useState<string | null>(null);

  function updateContent(value: string) {
    setContent(value);
    // Results describe the content they were produced from; never show them as current.
    setValidation(null);
    setPreview(null);
  }

  async function validate() {
    setBusy("validate");
    setError(null);
    try {
      setValidation(
        await api<PrivacyProfileValidation>("/api/privacy-profiles/validate", {
          method: "POST",
          body: JSON.stringify({ content })
        })
      );
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Validation failed.");
    } finally {
      setBusy(null);
    }
  }

  async function runPreview() {
    if (!sample.trim()) {
      setError("Enter a sample JSON event before previewing.");
      return;
    }
    if (new TextEncoder().encode(sample).length > maxSampleBytes) {
      setError("Preview sample cannot exceed 64 KiB.");
      return;
    }
    setBusy("preview");
    setError(null);
    try {
      setPreview(
        await api<PrivacyProfilePreview>("/api/privacy-profiles/preview", {
          method: "POST",
          body: JSON.stringify({ content, sample })
        })
      );
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Preview failed.");
    } finally {
      setBusy(null);
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const summary = changeSummary.trim();
    if (!content.trim()) {
      setError("Enter privacy profile YAML before submitting.");
      return;
    }
    if (!summary) {
      setError("Enter a change summary before submitting for review.");
      return;
    }
    setBusy("submit");
    setError(null);
    try {
      const detail = await api<PrivacyProfileVersionDetail>("/api/privacy-profiles", {
        method: "POST",
        body: JSON.stringify({ content, changeSummary: summary })
      });
      onSubmitted(detail);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Submission failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="sheet section-gap" aria-labelledby="privacy-editor-title">
      <div className="section-heading">
        <h2 id="privacy-editor-title">Submit new version</h2>
        <span>{basedOn ? `Prefilled from ${basedOn}` : "New privacy profile"}</span>
      </div>
      <div className="sheet-body">
        {error && (
          <div className="alert alert--danger" role="alert">
            {error}
          </div>
        )}
        <div className="parser-grid">
          <form className="parser-form" onSubmit={(event) => void submit(event)}>
            <label htmlFor="privacy-profile-content">Privacy profile YAML</label>
            <textarea
              id="privacy-profile-content"
              className="configuration-editor"
              value={content}
              spellCheck={false}
              autoCapitalize="off"
              autoComplete="off"
              aria-describedby="privacy-profile-content-help"
              onChange={(event) => updateContent(event.target.value)}
            />
            <p className="form-help" id="privacy-profile-content-help">
              Raise <code>metadata.version</code> (MAJOR.MINOR.PATCH) above every earlier
              version of this privacy profile. The submitted copy is immutable.
            </p>

            <label htmlFor="privacy-profile-summary">Change summary</label>
            <input
              id="privacy-profile-summary"
              type="text"
              value={changeSummary}
              maxLength={500}
              required
              aria-describedby="privacy-profile-summary-help"
              onChange={(event) => setChangeSummary(event.target.value)}
            />
            <p className="form-help" id="privacy-profile-summary-help">
              Required, up to 500 characters. Reviewers see it with the diff.
            </p>

            <div className="button-row">
              <button
                className="button button--secondary"
                type="button"
                disabled={busy !== null}
                onClick={() => void validate()}
              >
                <CheckCircle2 aria-hidden="true" />
                {busy === "validate" ? "Validating…" : "Validate"}
              </button>
              <button className="button button--primary" type="submit" disabled={busy !== null}>
                <Send aria-hidden="true" />
                {busy === "submit" ? "Submitting…" : "Submit for review"}
              </button>
              <button
                className="button button--secondary"
                type="button"
                disabled={busy === "submit"}
                onClick={onCancel}
              >
                Cancel
              </button>
            </div>

            <label htmlFor="privacy-profile-sample">Preview sample (JSON event)</label>
            <textarea
              id="privacy-profile-sample"
              value={sample}
              spellCheck={false}
              aria-describedby="privacy-profile-sample-help"
              placeholder='{"message":"user EMP-123456 logged in"}'
              onChange={(event) => {
                setSample(event.target.value);
                setPreview(null);
              }}
            />
            <p className="form-help" id="privacy-profile-sample-help">
              Up to 64 KiB. Processed in memory with a random key; never stored or logged.
            </p>
            <button
              className="button button--secondary"
              type="button"
              disabled={busy !== null}
              onClick={() => void runPreview()}
            >
              <Eye aria-hidden="true" />
              {busy === "preview" ? "Previewing…" : "Preview"}
            </button>
          </form>

          <div className="privacy-editor-side">
            {validation && <ValidationResult validation={validation} />}
            {preview && <PreviewResult preview={preview} />}
            <aside className="help-panel" aria-labelledby="custom-detector-help-title">
              <h3 id="custom-detector-help-title">Custom detector YAML</h3>
              <p>
                Custom detectors (custom redaction rules) add your own value patterns to the
                built-in detectors. Each custom detector needs an id that starts with{" "}
                <code>custom.</code>, a restricted <code>pattern</code>, an{" "}
                <code>action</code> and <code>tests</code>: every <code>tests.match</code>{" "}
                sample must match and no <code>tests.noMatch</code> sample may match, or the
                privacy profile is rejected.
              </p>
              <pre className="code-block" tabIndex={0} aria-label="Custom detector example">
                {customDetectorExample}
              </pre>
              <p>
                Lookaround, back-references, inline flags and Unicode properties are not
                supported. Full reference:{" "}
                <code>docs/privacy/custom-redaction-rules.md</code> in the Bower repository.
              </p>
            </aside>
          </div>
        </div>
      </div>
    </section>
  );
}

function ValidationResult({ validation }: { validation: PrivacyProfileValidation }) {
  if (!validation.valid) {
    return (
      <div className="alert alert--danger" role="status">
        <strong>Privacy profile is not valid.</strong>
        <ul className="result-list">
          {validation.errors.map((message, index) => (
            <li key={`${index}-${message}`}>{message}</li>
          ))}
        </ul>
      </div>
    );
  }
  return (
    <div className="result-panel" role="status">
      <h3>Validation passed</h3>
      <dl className="detail-list">
        <div>
          <dt>Privacy profile</dt>
          <dd className="mono">
            {validation.profileId ?? "—"}@{validation.version ?? "—"}
          </dd>
        </div>
        <div>
          <dt>Content hash</dt>
          <dd className="mono">{validation.contentHash ?? "—"}</dd>
        </div>
        <div>
          <dt>Detector overrides</dt>
          <dd>{validation.detectorOverrides}</dd>
        </div>
        <div>
          <dt>Field rules</dt>
          <dd>{validation.fieldRules}</dd>
        </div>
        <div>
          <dt>Secret field names</dt>
          <dd>{validation.secretFieldNames}</dd>
        </div>
        <div>
          <dt>Custom detectors</dt>
          <dd>{validation.customDetectors.length}</dd>
        </div>
      </dl>
      {validation.customDetectors.length > 0 && (
        <ul className="parser-tests section-gap" aria-label="Custom detectors">
          {validation.customDetectors.map((detector) => (
            <li key={detector.id}>
              <strong className="mono">{detector.id}</strong>
              <span>Action: {detector.action}</span>
              {detector.action === "AlertOnly" && (
                <span className="form-help">
                  Records matches without redacting them. Confirm this is intended.
                </span>
              )}
              {detector.description && <span>{detector.description}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function PreviewResult({ preview }: { preview: PrivacyProfilePreview }) {
  if (!preview.valid) {
    return (
      <div className="alert alert--danger" role="status">
        <strong>Preview could not run.</strong>
        <ul className="result-list">
          {preview.errors.map((message, index) => (
            <li key={`${index}-${message}`}>{message}</li>
          ))}
        </ul>
      </div>
    );
  }
  return (
    <div className="result-panel" role="status">
      <h3>Redacted preview</h3>
      <pre className="code-block" tabIndex={0} aria-label="Redacted output">
        {preview.redacted ?? ""}
      </pre>
      {preview.findings.length ? (
        <div className="responsive-table">
          <table>
            <caption className="visually-hidden">Preview findings</caption>
            <thead>
              <tr>
                <th>Detector</th>
                <th>Action</th>
                <th>Path</th>
              </tr>
            </thead>
            <tbody>
              {preview.findings.map((finding, index) => (
                <tr key={`${finding.path}-${finding.detectorId}-${index}`}>
                  <td data-label="Detector" className="mono">
                    {finding.detectorId}
                  </td>
                  <td data-label="Action">{finding.action}</td>
                  <td data-label="Path" className="mono">
                    {finding.path}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="form-help">No detector matched this sample.</p>
      )}
    </div>
  );
}
