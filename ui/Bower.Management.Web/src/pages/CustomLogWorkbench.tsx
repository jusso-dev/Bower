import { type ChangeEvent, useState } from "react";
import { useApi } from "../api";
import { EmptyState } from "../components/ui";
import type { CustomLogGeneration, CustomLogParserConfiguration, CustomLogPreview } from "../types";

export function CustomLogWorkbench() {
  const api = useApi();
  const [sourceMode, setSourceMode] = useState<"sample" | "path">("sample");
  const [sample, setSample] = useState("");
  const [path, setPath] = useState("");
  const [generation, setGeneration] = useState<CustomLogGeneration | null>(null);
  const [configuration, setConfiguration] = useState("");
  const [preview, setPreview] = useState<CustomLogPreview | null>(null);
  const [busy, setBusy] = useState<"generate" | "preview" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const input = {
    sample: sourceMode === "sample" ? sample : null,
    path: sourceMode === "path" ? path : null
  };

  async function generate() {
    setBusy("generate");
    setError(null);
    setGeneration(null);
    setPreview(null);
    try {
      const result = await api<CustomLogGeneration>("/api/custom-logs/generate", {
        method: "POST",
        body: JSON.stringify(input)
      });
      setGeneration(result);
      setConfiguration(JSON.stringify(result.configuration, null, 2));
      setPreview(result.preview);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Parser generation failed."
      );
    } finally {
      setBusy(null);
    }
  }

  async function validatePreview() {
    let parsedConfiguration: CustomLogParserConfiguration;
    try {
      parsedConfiguration = JSON.parse(configuration) as CustomLogParserConfiguration;
    } catch {
      setError("Parser configuration is not valid JSON.");
      return;
    }

    setBusy("preview");
    setError(null);
    try {
      const result = await api<CustomLogPreview>("/api/custom-logs/preview", {
        method: "POST",
        body: JSON.stringify({ input, configuration: parsedConfiguration })
      });
      setPreview(result);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Preview validation failed."
      );
    } finally {
      setBusy(null);
    }
  }

  async function selectFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    if (file.size > 256 * 1024) {
      setError("Sample file cannot exceed 256 KiB.");
      event.target.value = "";
      return;
    }
    setError(null);
    setSample(await file.text());
  }

  function downloadPackage() {
    if (!generation) {
      return;
    }
    let parsedConfiguration: CustomLogParserConfiguration;
    try {
      parsedConfiguration = JSON.parse(configuration) as CustomLogParserConfiguration;
    } catch {
      setError("Parser configuration is not valid JSON.");
      return;
    }
    const packageDocument = JSON.stringify(
      { configuration: parsedConfiguration, schema: generation.schema, tests: generation.tests },
      null,
      2
    );
    const url = URL.createObjectURL(
      new Blob([packageDocument], { type: "application/json" })
    );
    const anchor = window.document.createElement("a");
    anchor.href = url;
    anchor.download = "bower-custom-log-parser.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  const canGenerate =
    busy === null &&
    (sourceMode === "sample" ? sample.trim().length > 0 : path.trim().length > 0);

  return (
    <section className="custom-log-workbench" aria-labelledby="custom-log-title">
      <div className="subsection-heading">
        <div>
          <h2 id="custom-log-title">AI-assisted custom log parser</h2>
          <p>
            Deterministic, local inference. Samples are bounded, processed in memory
            and never persisted.
          </p>
        </div>
        <span>Operator role required</span>
      </div>

      <div className="parser-grid">
        <section className="sheet">
          <div className="section-heading">
            <h2>1. Provide sample</h2>
            <span>256 KiB · 200 lines</span>
          </div>
          <div className="sheet-body parser-form">
            <fieldset className="source-switch">
              <legend>Sample source</legend>
              <label>
                <input
                  type="radio"
                  name="source-mode"
                  checked={sourceMode === "sample"}
                  onChange={() => setSourceMode("sample")}
                />
                Upload or paste
              </label>
              <label>
                <input
                  type="radio"
                  name="source-mode"
                  checked={sourceMode === "path"}
                  onChange={() => setSourceMode("path")}
                />
                Server path
              </label>
            </fieldset>

            {sourceMode === "sample" ? (
              <>
                <label htmlFor="custom-log-file">Sample log file</label>
                <input
                  id="custom-log-file"
                  type="file"
                  accept=".log,.txt,.json,.jsonl,.csv,text/plain,application/json,text/csv"
                  onChange={(event) => void selectFile(event)}
                />
                <label htmlFor="custom-log-sample">Sample records</label>
                <textarea
                  id="custom-log-sample"
                  value={sample}
                  onChange={(event) => setSample(event.target.value)}
                  placeholder='{"timestamp":"2026-07-29T10:00:00Z","severity":"warning","user":"alex","source_ip":"192.0.2.10","action":"login"}'
                  spellCheck={false}
                />
              </>
            ) : (
              <>
                <label htmlFor="custom-log-path">Path on Bower server</label>
                <input
                  id="custom-log-path"
                  type="text"
                  value={path}
                  onChange={(event) => setPath(event.target.value)}
                  placeholder="/var/log/example/security.log"
                  spellCheck={false}
                />
                <p className="form-help">
                  Path must be under a root listed in{" "}
                  <code>BOWER_CUSTOM_LOG_ROOTS</code>. Symbolic links are rejected.
                </p>
              </>
            )}

            <button
              className="button button--primary"
              type="button"
              disabled={!canGenerate}
              onClick={() => void generate()}
            >
              {busy === "generate" ? "Inferring…" : "Infer parser and schema"}
            </button>
          </div>
        </section>

        <section className="sheet">
          <div className="section-heading">
            <h2>2. Review inference</h2>
            <span>
              {generation
                ? `${generation.format} · ${Math.round(generation.confidence * 100)}%`
                : "Awaiting sample"}
            </span>
          </div>
          {generation ? (
            <div className="sheet-body">
              <ul className="compact-list">
                {generation.rationale.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
              <div className="responsive-table section-gap">
                <table>
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Type</th>
                      <th>OCSF</th>
                      <th>ASIM</th>
                      <th>Required</th>
                    </tr>
                  </thead>
                  <tbody>
                    {generation.schema.fields.map((field) => (
                      <tr key={field.name}>
                        <td data-label="Source" className="mono">
                          {field.name}
                        </td>
                        <td data-label="Type">{field.type}</td>
                        <td data-label="OCSF" className="mono">
                          {field.ocsfPath ?? "unmapped"}
                        </td>
                        <td data-label="ASIM" className="mono">
                          {field.asimField ?? "unmapped"}
                        </td>
                        <td data-label="Required">{field.required ? "Yes" : "No"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <EmptyState
              title="No parser generated"
              detail="Provide representative records. Include at least two rows for CSV inference."
            />
          )}
        </section>
      </div>

      {error && (
        <div className="alert alert--danger" role="alert">
          <strong>Custom log parser request failed.</strong>
          <span>{error}</span>
        </div>
      )}

      {generation && (
        <div className="parser-grid section-gap">
          <section className="sheet">
            <div className="section-heading">
              <h2>3. Validate configuration</h2>
              <span>Version {generation.configuration.version}</span>
            </div>
            <div className="sheet-body parser-form">
              <label htmlFor="parser-configuration">Parser configuration</label>
              <textarea
                id="parser-configuration"
                className="configuration-editor"
                value={configuration}
                onChange={(event) => setConfiguration(event.target.value)}
                spellCheck={false}
              />
              <div className="button-row">
                <button
                  className="button button--primary"
                  type="button"
                  disabled={busy !== null}
                  onClick={() => void validatePreview()}
                >
                  {busy === "preview" ? "Validating…" : "Validate live preview"}
                </button>
                <button
                  className="button button--secondary"
                  type="button"
                  onClick={downloadPackage}
                >
                  Download config, schema and tests
                </button>
              </div>
            </div>
          </section>

          <section className="sheet">
            <div className="section-heading">
              <h2>Generated parser tests</h2>
              <span>{generation.tests.length} assertions</span>
            </div>
            <div className="sheet-body">
              <ol className="parser-tests">
                {generation.tests.map((test) => (
                  <li key={test.name}>
                    <strong>{test.name}</strong>
                    <span>
                      {test.shouldParse ? "accept" : "reject"}
                      {test.sourceLine ? ` · sample line ${test.sourceLine}` : ""}
                    </span>
                    {test.expectedFields.length > 0 && (
                      <code>{test.expectedFields.join(", ")}</code>
                    )}
                  </li>
                ))}
              </ol>
            </div>
          </section>
        </div>
      )}

      {preview && (
        <section className="sheet section-gap">
          <div className="section-heading">
            <h2>Live transformation preview</h2>
            <span>
              {preview.isValid ? "Valid" : "Needs review"} · {preview.parsedLineCount}{" "}
              parsed · {preview.rejectedLineCount} rejected
            </span>
          </div>
          <div className="sheet-body">
            <p className="form-help">
              Identity, IP, path, message and unmapped values stay redacted. Preview
              proves parsing and mappings only; it does not deploy or prove Sentinel
              delivery.
            </p>
            {preview.issues.length > 0 && (
              <ul className="preview-issues">
                {preview.issues.map((issue) => (
                  <li key={issue}>{issue}</li>
                ))}
              </ul>
            )}
            <div className="preview-grid">
              {preview.rows.map((row) => (
                <article key={row.sourceLine} className="preview-row">
                  <h3>Source line {row.sourceLine}</h3>
                  <dl>
                    {Object.entries(row.fields).map(([name, field]) => (
                      <div key={name}>
                        <dt>
                          <code>{name}</code>
                          <span>{field.ocsfPath ?? field.asimField ?? "unmapped"}</span>
                        </dt>
                        <dd>{field.value}</dd>
                      </div>
                    ))}
                  </dl>
                </article>
              ))}
            </div>
          </div>
        </section>
      )}
    </section>
  );
}
