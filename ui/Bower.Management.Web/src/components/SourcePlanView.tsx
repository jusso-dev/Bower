import { Copy } from "lucide-react";
import { useState } from "react";
import { shortHash } from "../lib/format";
import type { SourceSetupPlan, SourceSetupPreview } from "../types";

/** Copies text to the clipboard (never browser storage) and says so politely. */
export function CopyButton({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  return (
    <span className="copy-button">
      <button
        className="button button--secondary"
        type="button"
        onClick={() => {
          if (!navigator.clipboard) {
            setState("failed");
            return;
          }
          navigator.clipboard.writeText(text).then(
            () => setState("copied"),
            () => setState("failed")
          );
        }}
      >
        <Copy aria-hidden="true" />
        {label}
      </button>
      <span className="form-help" role="status" aria-live="polite">
        {state === "copied" ? "Copied." : state === "failed" ? "Copy is not available here: select the text and copy it." : ""}
      </span>
    </span>
  );
}

function CodeBlock({ label, text }: { label: string; text: string }) {
  // Scrollable regions are focusable so keyboard users can scroll them.
  return (
    <pre className="code-block" tabIndex={0} aria-label={label}>
      {text}
    </pre>
  );
}

/** What a source setup installs: files, environment variables and copy-paste snippets. */
export function SourcePlanView({ plan, headingLevel = 3 }: { plan: SourceSetupPlan; headingLevel?: 3 | 4 }) {
  const Heading = headingLevel === 3 ? "h3" : "h4";
  const components = [...new Set(plan.variables.map((variable) => variable.component))];
  return (
    <div className="source-plan">
      <p className="form-help">
        Content hash <code title={plan.contentHash}>{shortHash(plan.contentHash)}</code>. An approval covers
        exactly this content.
      </p>
      {plan.files.map((file) => (
        <section className="source-plan__item" key={file.name}>
          <Heading>
            {file.name} <span className="source-plan__where">→ {file.installPath}</span>
          </Heading>
          <p className="form-help">{file.description}</p>
          <CodeBlock label={`Contents of ${file.name}`} text={file.content} />
          <CopyButton text={file.content} label={`Copy ${file.name}`} />
        </section>
      ))}
      {components.map((component) => {
        const lines = plan.variables
          .filter((variable) => variable.component === component)
          .map((variable) => `${variable.name}=${variable.value}`)
          .join("\n");
        return (
          <section className="source-plan__item" key={component}>
            <Heading>Settings for the {componentName(component)}</Heading>
            <p className="form-help">Environment variables, for example in its service or container definition.</p>
            <CodeBlock label={`Environment variables for the ${componentName(component)}`} text={lines} />
            <CopyButton text={lines} label="Copy settings" />
          </section>
        );
      })}
      {plan.snippets.map((snippet) => (
        <section className="source-plan__item" key={snippet.title}>
          <Heading>{snippet.title}</Heading>
          <p className="form-help">{snippet.description}</p>
          <CodeBlock label={snippet.title} text={snippet.content} />
          <CopyButton text={snippet.content} label="Copy snippet" />
        </section>
      ))}
    </div>
  );
}

function componentName(component: string) {
  return component === "collector" ? "collector" : component === "cloud-forwarder" ? "cloud forwarder" : component;
}

/** The synthetic sample after redaction. Raw sample values never reach the browser. */
export function SourcePreviewView({ preview }: { preview: SourceSetupPreview }) {
  if (!preview.valid || !preview.redacted) {
    return <p className="alert">Bower could not build a preview for these settings.</p>;
  }
  return (
    <div className="source-plan__item">
      <p className="form-help">
        A made-up event of this kind after Bower's privacy rules, exactly as the collector would store it.
        It holds no real data. Rules: {preview.rules}
      </p>
      <CodeBlock label="Example event after redaction" text={pretty(preview.redacted)} />
      {preview.findings.length > 0 && (
        <ul className="source-plan__findings" aria-label="What Bower protected">
          {preview.findings.map((finding) => (
            <li key={`${finding.path}-${finding.detectorId}`}>
              <code>{finding.path}</code>: {finding.action} ({finding.detectorId})
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function pretty(json: string) {
  try {
    return JSON.stringify(JSON.parse(json), null, 2);
  } catch {
    return json;
  }
}
