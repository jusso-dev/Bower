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
