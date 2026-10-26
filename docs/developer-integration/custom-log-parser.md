# Custom log parser generator

Bower Management provides AI-assisted inference for a declarative parser and
field schema from a bounded custom application log sample. Assistance runs as a
deterministic local classifier: no sample is sent to an external model. This is
an operator-assisted design tool. It does not deploy a source adapter, persist
the sample, or claim Microsoft Sentinel delivery.

## Supported inference

- JSON objects, JSON arrays and JSON Lines, including scalar fields nested to
  four levels.
- CSV with comma, tab or semicolon delimiters and a stable header.
- Whitespace-separated `key=value` or `key:value` records, including quoted
  values.
- Bounded regular expressions for common HTTP access logs, RFC 3164-style
  syslog and timestamp/severity/message records.

Inference identifies timestamps, severities, user identities, source and
destination IP addresses, actions, outcomes, hosts, applications, process IDs,
URLs and messages. Known fields receive OCSF and ASIM targets. Unrecognised
fields remain explicit and unmapped for operator review.

## Use the console

Open **Pipelines → Custom log parser** with `Bower.Operator`,
`Bower.Approver` or `Bower.Administrator`.

1. Upload or paste a sample, or enter a path on the Bower Management server.
2. Review detected format, confidence, field types, OCSF targets and ASIM
   targets.
3. Edit generated JSON configuration if needed.
4. Run **Validate live preview**.
5. Download configuration, inferred schema and generated assertions for review
   and source-adapter deployment.

Preview values for identities, IP addresses, URLs, messages and unmapped fields
are redacted. Preview proves parsing and mapping only. Destination query
validation remains required before claiming Sentinel delivery.

### Preview privacy floor

Bower Management applies a minimum preview privacy policy that the submitted
configuration cannot lower. Setting `sensitive: false` or assigning any OCSF or
ASIM mapping can add masking but never removes it. Whatever the configuration
says, a preview value stays redacted when:

- the field type is `IpAddress`, or the value contains an IPv4 (dotted quad) or
  IPv6 address, in any format;
- the source field name is not one of the known non-sensitive names (timestamp,
  severity, action, outcome, application and process ID aliases). This applies
  to every type: an unknown whole number, boolean or date is masked too;
- the source field name is credential-like or describes identity, network or
  account data (for example `user`, `email`, `client_ip`, `host`, `url`,
  `message`, `account`, `session`, `phone`);
- the field type is `Text` and the value is longer than 64 characters or
  contains characters other than letters, digits and `. _ - : +`;
- a built-in privacy detector (Australian identifiers, financial, identity
  including IP, hostname and username, secrets and cryptographic material) finds
  sensitive data in the value. Public identifiers the default privacy policy
  allows (ABN, ACN, SWIFT BIC) are not counted.

Regex parsers get stricter rules, because the operator's pattern decides what
each capture holds:

- With an operator-authored pattern (anything other than the built-in HTTP
  access-log, timestamp/severity and syslog patterns), no value previews. Every
  configured field appears in every row as redacted, whether or not its group
  took part in the match, so captures carry no per-line information.
- With a built-in pattern, a `Text` capture previews only when it is a closed
  vocabulary word (a severity level, an HTTP method, an outcome word such as
  `success`, `failure`, `allow`, `deny`, `accepted` or `rejected`, or a
  three-digit status code). A capture that overlaps sensitive data that a
  detector finds in the whole source line stays masked.
- A zero-length capture is treated as a group that did not take part.

Field names come from the sample too. A JSON key, key/value key or CSV header
that contains an IP address, an all-digit segment (such as `counts.1002`) or
anything a detector finds is renamed to a neutral `field_N` alias, numbered in
order of first appearance, and the original name is never returned. A CSV whose
first row contains a number, boolean, date, IP address or detected value is
not treated as having a header row.

Pasted samples and server-path samples get the same floor. Timestamps, process
IDs, severities, HTTP methods and status codes under the known names still
preview. Preview issues and errors are Bower-authored and never echo sample
values.

### Transforms

A configuration can carry a signed transform program in `runtime.transforms` (see the
[transform language reference](transform-language.md)). Preview validates it and
reports metadata-only issues (statement, column and code), but never runs it: preview
rows always show the source fields under the floor above, so a transform cannot derive
or reveal a value preview would otherwise mask. Transforms run only at collector intake,
before redaction, and only in signed packs.

## Point Bower at a server file

Server-path input is disabled unless one or more roots are configured:

```bash
export BOWER_CUSTOM_LOG_ROOTS=/var/log/apps:/srv/bower/samples
```

Use the platform path separator (`:` on Unix, `;` on Windows). Bower resolves
absolute paths, rejects paths outside configured roots and rejects symbolic
links within the selected path.

## Security and limits

- Maximum sample: 256 KiB, 200 non-empty lines, 32 KiB per line.
- Maximum generated schema: 64 fields.
- Samples are read into memory for the current request and are not persisted.
- Credential-like fields such as passwords, tokens, cookies, authorization
  values, payloads and unrestricted bodies are excluded.
- Generated and edited regular expressions run through .NET's non-backtracking
  engine with a 100 ms timeout. Unsupported constructs fail validation.
- Configuration stays declarative and cannot execute scripts.
- Both generation and preview endpoints require the API `Operate` policy.

Versioned configuration shape:
[`schemas/custom-log-parser-config.schema.json`](../../schemas/custom-log-parser-config.schema.json).

## API

Generate from inline sample:

```http
POST /api/custom-logs/generate
Content-Type: application/json

{
  "sample": "{\"timestamp\":\"2026-07-29T10:00:00Z\",\"severity\":\"warning\",\"action\":\"login\"}",
  "path": null
}
```

Generate from server path:

```json
{
  "sample": null,
  "path": "/var/log/apps/security.jsonl"
}
```

Validate an edited configuration with `POST /api/custom-logs/preview`:

```json
{
  "input": {
    "sample": "{\"severity\":\"warning\"}",
    "path": null
  },
  "configuration": {
    "version": "1.0",
    "format": "Json",
    "fields": [
      {
        "sourceName": "severity",
        "type": "Text",
        "ocsfPath": "severity",
        "asimField": "EventSeverity",
        "sensitive": false
      }
    ],
    "delimiter": null,
    "keyValueSeparator": null,
    "pattern": null
  }
}
```
