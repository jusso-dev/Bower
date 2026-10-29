import type { GuidedCheck, SourceFieldDefinition, SourceTypeDefinition } from "../types";

/*
 * One generic form for every guided source type. Field definitions come from
 * /api/sources/types; the server re-checks every value, so the kinds here only guide input.
 * Secret fields take where a secret lives (a file path or Key Vault URL), never the secret.
 */

/** Default values of a source type's fields, for a new form. */
export function initialSourceValues(type: SourceTypeDefinition): Record<string, string> {
  return Object.fromEntries(type.fields.map((field) => [field.id, field.defaultValue ?? ""]));
}

/** True when the field is shown for the current values (for example TLS files only for TLS). */
export function sourceFieldVisible(field: SourceFieldDefinition, values: Record<string, string>): boolean {
  if (!field.shownWhenField) {
    return true;
  }
  return (field.shownWhenValues ?? []).includes(values[field.shownWhenField] ?? "");
}

/** Only the values of visible fields are sent (the server also ignores hidden ones). */
export function visibleSourceValues(type: SourceTypeDefinition, values: Record<string, string>) {
  return Object.fromEntries(
    type.fields
      .filter((field) => sourceFieldVisible(field, values))
      .map((field) => [field.id, values[field.id] ?? ""])
  );
}

export function SourceForm({
  type,
  values,
  checks,
  disabled,
  onChange
}: {
  type: SourceTypeDefinition;
  values: Record<string, string>;
  /** Server checks; a failing check whose id is a field id shows next to that field. */
  checks: GuidedCheck[];
  disabled: boolean;
  onChange: (id: string, value: string) => void;
}) {
  return (
    <div className="source-form">
      {type.fields
        .filter((field) => sourceFieldVisible(field, values))
        .map((field) => (
          <SourceField
            key={field.id}
            field={field}
            value={values[field.id] ?? ""}
            problem={checks.find((check) => check.id === field.id && check.state === "fail")}
            disabled={disabled}
            onChange={(value) => onChange(field.id, value)}
          />
        ))}
    </div>
  );
}

function SourceField({
  field,
  value,
  problem,
  disabled,
  onChange
}: {
  field: SourceFieldDefinition;
  value: string;
  problem: GuidedCheck | undefined;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  const id = `source-field-${field.id}`;
  const describedBy = `${id}-help${problem ? ` ${id}-problem` : ""}`;
  const label = field.label;
  const help = (
    <>
      <p className="form-help" id={`${id}-help`}>
        {field.required ? "Required. " : ""}
        {field.help}
        {field.kind === "secret-reference" && (
          <>
            {" "}
            <strong>
              {field.keyVaultAllowed
                ? "Enter a file path or Key Vault secret URL, never the secret itself."
                : "Enter the file path, never the secret itself."}
            </strong>
          </>
        )}
      </p>
      {problem && (
        <p className="form-problem" id={`${id}-problem`}>
          {problem.message} {problem.fix}
        </p>
      )}
    </>
  );

  if (field.kind === "choice") {
    return (
      <fieldset className="choice-list" aria-describedby={describedBy}>
        <legend>{label}</legend>
        {(field.options ?? []).map((option) => (
          <label className="choice-list__item" key={option.value}>
            <input
              type="radio"
              name={id}
              value={option.value}
              checked={value === option.value}
              disabled={disabled}
              onChange={() => onChange(option.value)}
            />
            <span>{option.label}</span>
          </label>
        ))}
        {help}
      </fieldset>
    );
  }

  if (field.kind === "boolean") {
    return (
      <div className="source-form__boolean">
        <label htmlFor={id}>
          <input
            id={id}
            type="checkbox"
            checked={value === "true"}
            disabled={disabled}
            aria-describedby={describedBy}
            onChange={(event) => onChange(event.target.checked ? "true" : "false")}
          />
          {label}
        </label>
        {help}
      </div>
    );
  }

  const list = field.kind === "address-list" || field.kind === "name-list";
  return (
    <div className="source-form__field">
      <label htmlFor={id}>{label}</label>
      {list ? (
        <textarea
          id={id}
          value={value}
          rows={3}
          maxLength={field.maximumLength}
          placeholder={field.placeholder ?? undefined}
          disabled={disabled}
          spellCheck={false}
          aria-describedby={describedBy}
          aria-invalid={problem ? true : undefined}
          onChange={(event) => onChange(event.target.value)}
        />
      ) : (
        <input
          id={id}
          type={field.kind === "number" ? "number" : "text"}
          inputMode={field.kind === "number" ? "numeric" : undefined}
          min={field.minimum ?? undefined}
          max={field.maximum ?? undefined}
          value={value}
          maxLength={field.kind === "number" ? undefined : field.maximumLength}
          placeholder={field.placeholder ?? undefined}
          disabled={disabled}
          autoComplete="off"
          spellCheck={false}
          aria-describedby={describedBy}
          aria-invalid={problem ? true : undefined}
          onChange={(event) => onChange(event.target.value)}
        />
      )}
      {help}
    </div>
  );
}
