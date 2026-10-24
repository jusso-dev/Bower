# Custom redaction rules

A **privacy profile** controls how the [Privacy & Secret Protection
Engine](privacy-secret-engine.md) redacts events before anything is stored or
forwarded. On top of the built-in detectors, a privacy profile can define your own
redaction rules:

| Rule | YAML key | Use it for |
|---|---|---|
| **Custom detector** | `customDetectors` | Organisation-specific identifiers found *anywhere* in an event (employee numbers, customer references, ticket ids) |
| **Secret field names** | `secretFieldNames` | Extra property names whose values are always secrets (`sessionKey`, `x-contoso-signature`) |
| **Field rule** | `fields` | A known field path that needs a specific action (`actor.username: hmac`) |
| **Detector override** | `detectors` / `disabled` / `enableOptIn` | Changing what a built-in detector does |

Custom detectors are the custom redaction rules: this guide calls them *custom
detectors* from here on. They are deterministic, cannot execute code, and run in
every Bower host the same way: .NET and Rust collectors, the Azure Functions
collector, the AWS Lambda host, `bower privacy validate` and the management console
preview.

## 1. Write the rule

Start from [`deploy/privacy/custom-redaction-example.yaml`](../../deploy/privacy/custom-redaction-example.yaml):

```yaml
apiVersion: bower.security/v1
kind: PrivacyProfile
metadata:
  id: contoso-custom-redaction
  version: 1.0.0
  description: Contoso identifiers on top of the default Australian redaction.
customDetectors:
  - id: custom.employee-id
    description: Contoso employee numbers (EMP- and six digits).
    pattern: 'EMP-\d{6}'
    wholeWord: true
    action: mask
    tests:
      match: ["EMP-123456", "user EMP-000001 logged in"]
      noMatch: ["EMP-12345", "XEMP-123456", "EMP-1234567"]
  - id: custom.customer-ref
    pattern: 'CUST-[A-Z]{2}\d{4}'
    ignoreCase: true
    action: hmac            # needs BOWER_PRIVACY_HMAC_KEY_FILE on the host
    tests:
      match: ["CUST-AB1234", "ref cust-xy0001 opened"]
secretFieldNames: [sessionKey, x-contoso-signature]
fields:
  - path: actor.username
    action: hmac
```

Editors that understand JSON Schema can validate the file with
[`schemas/privacy-profile.schema.json`](../../schemas/privacy-profile.schema.json)
(for example `# yaml-language-server: $schema=../../schemas/privacy-profile.schema.json`).

### Custom detector fields

| Field | Required | Rules |
|---|---|---|
| `id` | yes | `custom.<name>`: lowercase letters, digits and single hyphens, at most 64 characters, unique |
| `description` | no | At most 256 characters. Shown to reviewers |
| `pattern` | yes | 1–512 characters, [restricted syntax](#pattern-syntax) |
| `ignoreCase` | no | `false` by default. ASCII letters only; non-ASCII stays case-sensitive |
| `wholeWord` | no | `false` by default. Keeps a match only when the characters either side are not ASCII letters, digits or `_` |
| `action` | yes | Any [action](privacy-secret-engine.md#actions): `allow`, `remove`, `replace`, `mask`, `sha256`, `hmac`, `encrypt`, `alert-only` |
| `tests.match` | yes | 1–16 samples (1–1024 characters each). **Every sample must match** |
| `tests.noMatch` | no | 0–16 samples. **No sample may match** |

What a custom detector does at runtime:

- It scans string values, number values (their exact JSON text) and property names,
  exactly like the built-in value detectors, after them, in the order you list them.
- It is on by default. Turn one off with `disabled: [custom.employee-id]`.
- When a custom detector and a built-in detector match the same text, the longer
  match wins; an equal-length match goes to the built-in detector.
- Findings appear in the event's `privacy` metadata as the custom id and action, never
  the original value.
- Custom detectors do **not** raise the `sensitive_data_detected` security alert.
  Only the built-in high-risk detectors do.
- Set the action in `customDetectors`. Listing a custom id under `detectors:` or
  `enableOptIn:` fails the load.

### Secret field names

`secretFieldNames` (at most 64, each 1–128 characters) adds names to the built-in
field-name secret detector. Names are compared after normalisation: letters and
digits only, lower case. So `sessionKey`, `session_key` and `SESSION-KEY` are the
same name. A matching property is handled exactly like a built-in secret field name:
detector id `field-name-secret`, removed by default.

## Pattern syntax

Patterns use a restricted, portable regular expression syntax. Bower translates it
into one canonical pattern that the .NET and Rust engines evaluate identically, in
linear time (no backtracking).

| You can write | Meaning |
|---|---|
| Literal characters, `\.` `\-` `\ ` (escaped punctuation) | The character itself |
| `\d` `\w` `\s` and `\D` `\W` `\S` | ASCII only: `[0-9]`, `[0-9A-Z_a-z]`, ASCII whitespace, and their negations |
| `.` | Any character except a newline |
| `[abc]` `[^abc]` `[a-z0-9]` | Character classes; `\d` `\w` `\s` allowed inside |
| `(...)` `(?:...)` | Groups (captures are not used) |
| `*` `+` `?` `{n}` `{n,}` `{n,m}`, optional lazy `?` | Repetition, bounds at most 1000 |
| `a\|b` | Alternation |
| `^` `$` | Start and end of the **whole value** |

Rejected, with the position and reason in the error:

- lookaround, back-references, named groups, inline flags (`(?i)`) and other `(?`
  constructs;
- `\b` and `\B` (use `wholeWord: true`), `\A` `\z` `\Z` `\G` (use `^` and `$`);
- Unicode properties (`\p{L}`), `\x` `\u` and other escapes;
- nested classes, POSIX classes (`[:alpha:]`) and class set operations (`&&`, `--`);
- characters outside the Basic Multilingual Plane (emoji) inside the pattern;
- patterns that can match an empty string (`a*`, `(a|)`), and patterns whose
  expansion estimate exceeds 512 (for example `[^\n]{600}`). Broad, long repetitions
  are slow on large values in every engine; keep patterns specific.

Matching is always against the event value as text. A match that would split an
emoji (a UTF-16 surrogate pair) is skipped.

### Limits

| Limit | Value |
|---|---|
| Custom detectors per privacy profile | 32 |
| Pattern length | 512 characters |
| Repetition bound | 1000 |
| Complexity estimate | 512 |
| Test samples | 16 `match` + 16 `noMatch`, 1024 characters each |
| Secret field names | 64, 128 characters each |
| Privacy profile size | 256 KiB |
| .NET match timeout | 100 ms per match; a timeout quarantines the event (`redaction-failed`), never forwards it unredacted |

## 2. Test the rule locally

The privacy profile is validated whenever it is loaded. Every `tests.match` and
`tests.noMatch` sample runs against its custom detector, so a collector refuses to
start with a broken rule rather than redact wrongly. Run the same check yourself:

```bash
bower privacy validate deploy/privacy/custom-redaction-example.yaml
bower privacy validate my-profile.yaml --sample sample-event.json --hmac-key-file hmac.key
```

`bower privacy validate` prints a metadata-only JSON summary (`profileId`,
`version`, `hash`, custom detector ids and actions, `secretFieldNames` count,
`testsPassed`). With `--sample` it also prints the redacted sample. Exit code `0`
means the profile is valid, `1` invalid (the reason is on stderr), `2` the sample
could not be redacted. Without `--hmac-key-file` a random key is used, so HMAC
pseudonyms differ between runs.

From PowerShell (`Bower.Privacy` module):

```powershell
Test-BowerPrivacyProfile -Path ./my-profile.yaml -SamplePath ./sample-event.json
New-BowerCustomDetector -Id custom.employee-id -Pattern 'EMP-\d{6}' -Action Mask `
    -WholeWord -Match 'EMP-123456' -NoMatch 'EMP-12345'
```

## 3. Version and review it

Treat a privacy profile like code:

1. Keep it in version control. Bump `metadata.version` (`MAJOR.MINOR.PATCH`) for
   every change. The privacy profile hash (`sha256:` over the YAML) changes with any
   edit and is what collectors report.
2. Run `bower privacy validate` in CI on every change.
3. Review the diff and the test samples. A reviewer should be able to read what each
   custom detector catches from its `description`, `tests.match` and `tests.noMatch`.

To review, approve and roll the privacy profile out to collectors from the
management console, with a second person approving every version, see [managed
privacy profiles](managed-privacy-profiles.md).

## 4. Deploy it

Pick one source per host. Only one privacy profile can be active.

| Host | How |
|---|---|
| Collector (.NET or Rust), local file | `BOWER_PRIVACY_PROFILE=/etc/bower/privacy.yaml`, restart |
| Collector, management console | `BOWER_PRIVACY_PROFILE_SOURCE=management` ([managed privacy profiles](managed-privacy-profiles.md)) |
| Signed pack | `privacyProfile: privacy.yaml` in `pack.yaml` ([packs](../deployment/packs.md)) |
| Azure Functions collector | Package the file and set `privacyProfilePath` ([Azure Functions](../deployment/azure-function.md)) |
| AWS Lambda host | Package the file and set `BOWER_PRIVACY_PROFILE` ([AWS Lambda](../deployment/aws-lambda-cloudtrail-lake.md)) |

Profiles that use `hmac`, in any rule, need `BOWER_PRIVACY_HMAC_KEY_FILE` (32+
bytes, base64) and `BOWER_PRIVACY_HMAC_KEY_ID` on the host. Without the key the host
refuses to start. The key never appears in the privacy profile.

Confirm what is active with the collector's `/v1/status`
(`policy.privacyProfile`, `privacyProfileVersion`, `privacyProfileHash`,
`privacyProfileSource`).

## Troubleshooting

| Error | Fix |
|---|---|
| `Custom detector 'custom.x' did not match tests.match[0].` | The pattern does not match that sample. Check escaping and `wholeWord` |
| `Custom detector 'custom.x' matched tests.noMatch[1].` | The pattern is too broad. Anchor it or enable `wholeWord` |
| `...pattern has unsupported syntax at position 4: word boundaries are not supported; use wholeWord.` | Replace `\b` with `wholeWord: true` |
| `...pattern must not match an empty string.` | Use `+` or `{1,}` instead of `*` |
| `...pattern is too complex.` | Reduce large repetition bounds; make the pattern more specific |
| `...sets its action in customDetectors, not detectors.` | Remove the custom id from `detectors:` |
| Collector quarantines events with `redaction-failed` after a profile change | A pattern hit the .NET match timeout on a large value. Make it more specific |
