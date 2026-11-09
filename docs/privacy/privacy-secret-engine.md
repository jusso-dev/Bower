# Privacy & Secret Protection Engine

The Privacy & Secret Protection Engine inspects every event **after parse and before
persistence / normalisation**. It is a core control for preventing accidental
leakage of regulated Australian identifiers, credentials and cryptographic
material into downstream SIEM platforms.

```
Raw Event → Parser → Privacy & Secret Engine → Normalisation → Output
                         ├── Detect
                         ├── Validate
                         ├── Classify
                         └── Apply Policy
```

## Design principles

| Principle | How |
| --- | --- |
| Deterministic | Compiled regex, checksums, structure, entropy — **no AI at runtime** |
| Streaming / per-event | Events processed independently; safe under concurrent callers |
| Extensible | `ISensitiveDetector` plugins; provider API keys via pattern registry |
| Configurable | Global default action + per-detector overrides |
| Fail closed | Invalid / oversized payloads, duplicate keys, custom detector scan limits or match timeouts and any other detector or action failure → `redaction-failed` → quarantine. `RedactJson` / `RedactText` never throw; a policy that could fail at runtime (field rule path without segments, negative length, null replacement text or collections) is rejected when the engine is built |
| Complete coverage | String **and number** values are scanned, and so are **property names** |

## Semantic change values and URLs

Before persistence, the collector removes change values except the reviewed
`role_membership_changed` / `role` pair, and strip URL query, fragment and userinfo
content. These structural guards run even when value detectors are disabled.
See [SEC-01/SEC-05 migration](../security/producer-scopes.md) for exact scope,
limitations, producer authorization and treatment of existing queued events.

## Actions

| Action | Effect |
| --- | --- |
| `Allow` | Leave value unchanged (still recorded in metadata if detected) |
| `Remove` | Delete property (field-name) or replace span with empty |
| `Replace` | Replace with configured placeholder |
| `Mask` | Partial reveal (e.g. last 4 digits, email local-part). Generic masks keep two UTF-16 units at each end but never half of a surrogate pair: that end shrinks to one unit and the pair is starred |
| `Sha256` | `sha256:<hex>` |
| `Hmac` | `hmac-sha256:<hex>`; requires a 32+ byte key. The engine refuses to start if `Hmac` is configured without one |
| `Encrypt` | AES-GCM (`enc:aesgcm:…`); requires 32-byte key; else remove |
| `AlertOnly` | Detect only; do not rewrite |

## Default detector actions (production-oriented)

| Detector | Default |
| --- | --- |
| Field-name secrets | Remove |
| TFN | Mask (last 4 digits) |
| CRN / Medicare / IHI / Passport / Licence / DVA | Mask |
| ABN / ACN | Allow |
| Credit card | Remove |
| JWT / cloud secrets / API keys / PEM / DB / env | Remove |
| Email / phone / DOB | Mask |
| Security markings | AlertOnly (opt-in) |

Opt-in (disabled by default): IP, hostname, username, residential address, GPS,
security markings.

### Why TFNs are masked, not hashed

There are only about 10^8 valid TFNs, so anyone who can read Sentinel could hash
them all and reverse an unkeyed SHA-256. Use `Mask`, `Remove`, or `Hmac` with a
managed secret key. `Sha256` remains available for high-entropy values only.

### Privacy profiles, pseudonymisation and length limits

A **privacy profile** (YAML, `kind: PrivacyProfile`) changes detector actions, adds
field rules and defines custom redaction rules (custom detectors and secret field
names). Load one with `BOWER_PRIVACY_PROFILE`, inside a signed pack, or from the
management console ([managed privacy profiles](managed-privacy-profiles.md)). Only
one privacy profile is active per host:

```yaml
apiVersion: bower.security/v1
kind: PrivacyProfile
metadata: { id: ssh-gateway, version: 1.0.0 }
detectors:
  id.email: remove
fields:
  - path: actor.username      # keyed hash: joinable across events, not reversible
    action: hmac
  - path: request.userAgent
    action: truncate
    maxLength: 256
maximumFieldLength: 32768     # every longer string is truncated
```

`hmac` output is `hmac-sha256:<keyId>:<hex>` using the key in
`BOWER_PRIVACY_HMAC_KEY_FILE` (32+ bytes, base64) and `BOWER_PRIVACY_HMAC_KEY_ID`.
The same input and key always give the same pseudonym, so analysts can correlate
attempts by account; a different key (another tenant, or after rotation) gives
different pseudonyms. Keys never appear in profiles. A profile that uses `hmac`
without a key fails at start-up. Unknown detector ids, actions or keys fail the load,
and so do a missing `metadata` block and explicit nulls where a value is required
(`detectors: ~`, a null action or field rule): each is an `InvalidDataException`
with a message naming the problem.

Organisation-specific identifiers need no code: add `customDetectors` and
`secretFieldNames` to the privacy profile. See [custom redaction
rules](custom-redaction-rules.md) for syntax, limits, testing (`bower privacy
validate`) and deployment.

`maximumFieldLength` keeps values below the Logs Ingestion API's silent 64 KB
truncation, so Bower decides where a value is cut and records it as
`limit.field-length` in privacy metadata.

### Numbers and key names

Detectors run over the exact JSON text of numbers, so a card number or TFN sent
as a number (`"card": 4111111111111111`) is caught. A redacted number becomes a
string. Property names are scanned too: a sensitive key is renamed to its
redacted form (for example `a***@example.test`) or to `redacted-key-N` when the
action removes it or the redacted name already exists. Names are compared as
they will be written (an unpaired surrogate becomes U+FFFD), so the output never
holds duplicate keys.

### Field-name secrets

Properties are removed when their normalised name (lower case, letters and
digits only) is a known secret name (`password`, `apikey`, `headers`, …),
contains a secret fragment (`password`, `secret`, `token`, `apikey`,
`privatekey`, `cookie`, `credential`, `connectionstring`, `authorization`,
`signature`, `passphrase`), or ends in `pwd`, `pass`, `pin` or `otp`. Names that
describe a secret without holding it (`tokenType`, `passwordLastChanged`,
`secretName`, …) are allow-listed. Examples removed: `dbPassword`,
`sessionToken`, `idToken`, `setCookie`, `xApiKey`, `AWS_SECRET_ACCESS_KEY`.

## Metadata

When findings exist, the engine attaches (never with original values):

```json
{
  "privacy": {
    "detected": ["au.tfn", "secret.jwt", "id.email"],
    "actions": {
      "au.tfn": "Masked",
      "secret.jwt": "Removed",
      "id.email": "Masked"
    }
  }
}
```

`SecurityEventEnvelope.Privacy` maps the same shape.

## Security team notification

Redaction alone is not enough for operations. When **high-risk** detectors fire,
`SecurityEventProcessor` also enqueues a first-class semantic event:

| Field | Value |
| --- | --- |
| `eventCategory` | `privacy-control` |
| `eventType` | `sensitive_data_detected` |
| `eventAction` | `privacy.control.applied` |
| `target.id` | source event id |
| `privacy.detected` / `privacy.actions` | detector ids + actions only |

**Never** includes original TFNs, secrets, tokens or card numbers.

Alert-worthy by default (SOC signal):

- Australian regulated ids: TFN, CRN, Medicare, IHI, passport, licence, DVA
- Payment: credit card, BSB/account, IBAN, PayID
- Secrets / crypto / field-name secrets / env vars / API keys
- Protective security markings (when opt-in detector enabled)

**Not** alert-worthy by default (still redacted on the source event):

- Routine email / phone mask alone (noise for SOC; still in source `privacy` metadata)

Policy: `policies/default/sensitive-data-detected.yaml` (`BWR-POL-PRIVACY-DETECT`).
Sentinel / SIEM can alert on `eventType == sensitive_data_detected`.

The alert is also built for source events that fail validation (they are still
quarantined). Its `application` is copied from the source; a source with
`"application": null` gives an empty `application`, the same as empty names, and
the alert policy decides as usual (the default policy requires `application.name`,
so such an alert is not queued).

## Detector modules

### Australian identifiers

| Id | Validation |
| --- | --- |
| `au.tfn` | ATO 8/9-digit checksum |
| `au.crn` | Pattern only (9 digits + letter); Services Australia publishes no check-character algorithm, so findings report `Validated: false` |
| `au.medicare` | Medicare checksum + issue digit |
| `au.ihi` | `800360` + Luhn |
| `au.passport` | Format + contextual label |
| `au.driver-licence` | State-heuristic formats (context gated) |
| `au.abn` | ABN mod-89 |
| `au.acn` | ACN check digit |
| `au.dva` | DVA pattern |

### Financial

`fin.credit-card` (Luhn + network), `fin.bsb-account`, `fin.iban` (mod-97),
`fin.swift-bic`, `fin.payid`.

`fin.iban` conservatively checks the IBAN-shaped value and its mod-97 checksum. It
does not require a fixed country-code list, so checksum-valid non-IBAN strings can
also match; this avoids silently missing newly registered formats.

### UUIDs and dashless GUIDs

Structured number detectors (`au.*`, `fin.credit-card`, `fin.bsb-account`, `fin.iban`
and `fin.swift-bic`) never claim a match that lies wholly inside a **canonical
identifier token**: a UUID in 8-4-4-4-12 form or exactly 32 hexadecimal digits (either
case, any version), with the start or end of the value, or a character other than an
ASCII letter, digit, hyphen or underscore, on both sides. So `{…}`, `urn:uuid:…`,
quotes, spaces and other punctuation leave the UUID recognised, while `TFN-<uuid>`,
`<uuid>x`, `id_<uuid>`, a 13-character last group or a non-hex character make the whole
run an ordinary token that is scanned as before.

Without this rule about 1 in 450 random UUIDv4 values (8-digit first group passing the
TFN checksum, or rarely a Luhn-valid card number across the first three groups) and
about 1 in 1,800 dashless GUIDs (IBAN mod-97) were redacted. In a producer's `eventId`
that quarantines the event as `event-id-redacted`, and the retry can never succeed.
UUIDv7 values minted from August 2024 to the end of 2025 often have an all-digit
first group and were redacted about 1 time in 80.

What still applies inside a canonical identifier token:

- secret, crypto, classification, identity and custom detectors, field rules and
  length limits;
- every detector on matches that only partly overlap the token (for example a BSB
  and account number that runs into it).

Real identifiers are unaffected: a TFN, card number or IBAN written on its own, with
spaces or hyphens, or next to a UUID, is not part of a canonical identifier token.
The limit is deliberate: a producer that writes an eight-digit TFN as the first group
of a UUID (`10040680-0000-0000-0000-000000000000`) is not caught. Redaction stops
accidental disclosure; a producer that wants to leak data can encode it in many ways,
and no person writes a TFN, card number or IBAN as a UUID. If you need to treat
UUID-shaped values as sensitive, add a custom detector; custom detectors still see them.

The exemption follows the token, not the words around it. A labelled value whose
digits form a canonical token, such as `TFN: 10040680-0000-0000-0000-000000000000` or
`passport A1234567-0000-0000-0000-000000000000`, is exempt too, within the same
accepted limit: the label does not turn the UUID back into a TFN or passport number.
Add a custom detector if your data writes identifiers that way.

Only a bare token is exempt. An id with a prefix or suffix joined by a hyphen,
underscore, letter or digit is one longer token and is scanned as before:
`evt-<uuid>`, `order-<uuid>`, `<uuid>-1` and AWS X-Ray-style trace ids
(`1-67123456-<24 hex digits>`) can still pass a checksum by chance and be quarantined
as `event-id-redacted`, about 1 time in 450 for a random UUIDv4 inside them.
Producers should send a bare UUID (or a UUIDv7) as `eventId` and carry any prefix in
another field.

The custom-log parser preview (`CustomLogParser`) does not apply this exemption: its
privacy floor masks any sample value a built-in detector matches, so a UUID that passes
a checksum stays masked in the preview. That is deliberate. The preview only hides
sample values from the console and never quarantines an event, so masking more is the
safe side, and the floor stays a plain "any detector match" rule that a configuration
cannot argue its way around.

The rule is engine behaviour, not profile content, so privacy profile versions and
hashes do not change. `CanonicalIdentifierTokens` implements it, pinned by the shared
parity vectors.

### Bower-generated identifiers and counters

Record ids that Bower's own syslog and Windows Event Log sources compute (`syslog-` or
`winevt-` plus 32 lowercase hex characters of a SHA-256 digest) skip value detectors in
the top-level `eventId` and `eventOriginalId`, when the value still equals the id the
source computed. Collector-generated `bower-canary-` IDs receive the same root-field
protection when the management worker supplies its own ID. The generated-ID validator accepts any prefix of 1–16 lowercase
letters, or the exact `bower-canary` prefix, a hyphen and 32 lowercase hexadecimal
characters; trusted callers must
still supply only IDs they actually generated. Numbers and all other values are still scanned, including values in
records Bower builds itself. Field rules and length limits still apply; producer-supplied
values and every other field are scanned as before. A changed event ID is never
acknowledged: the source must retain and retry it after the privacy configuration
is corrected. UDP syslog cannot retry a refused datagram; monitor its drop counter.

Redaction and pack-detection failures also stop processing without persisting the
event. HTTP ingestion returns 503 with a retry interval; WEC retains its bookmark,
and TCP/TLS syslog holds the frame while the connection remains open. Syslog has no
application-level acknowledgement, so senders must retain and replay after a lost
connection. A persistent privacy collision requires operator remediation; retries
alone do not repair it. These refusals do not create a privacy alert event, so monitor
source silence, retry and drop counters, and the authorized bounded operator tap.

Proven invalid inputs, including duplicate object properties encountered during
redaction and custom detector scan or match bounds, are quarantined with the bounded
reason `redaction-invalid-input` and are not retried. Source adapters may advance or
drop those records; monitor their rejection counters. Operational failures and
failures without a proven origin remain retryable. A caught detector exception is
operational even when it shares the same internal failure code as invalid input.

`RedactionContext` is a public in-process API, not a security boundary against code
running inside the collector. Only collector-owned source code may set the generated
ID. Never populate it from a producer-controlled value: doing so bypasses value
detectors for matching root identity fields. HTTP and other untrusted producer paths
must use the default context.

### Identity

`id.email`, `id.phone.au`, `id.phone.intl`, `id.dob`, plus optional
`id.address`, `id.gps`, `id.ip`, `id.hostname`, `id.username`.

### Secrets & crypto

AWS, Azure, Entra, GCP, JWT, OAuth, provider API keys (OpenAI, Anthropic,
GitHub, GitLab, Slack, Stripe, Twilio, Cloudflare, Atlassian, Datadog,
PagerDuty, Okta, MongoDB, Snowflake), Kubernetes, Docker, database connection
strings, environment variable assignments, PEM/PKCS8/SSH/PGP/X.509.

`crypto.material` sub-kinds come from the exact `-----BEGIN <label>-----` header
(body text never changes them) and appear in metadata as
`crypto.material:<sub-kind>`:

| Header label | Sub-kind |
| --- | --- |
| `RSA PRIVATE KEY` | `rsa-private` |
| `EC PRIVATE KEY` | `ecdsa-private` |
| `DSA PRIVATE KEY` | `dsa-private` |
| `OPENSSH PRIVATE KEY` | `openssh-private` |
| `ENCRYPTED PRIVATE KEY` | `encrypted-private` |
| `PRIVATE KEY` | `pkcs8-private` |
| `CERTIFICATE` | `x509-certificate` |
| `PGP PRIVATE KEY BLOCK` | `pgp-private` |
| `PGP PUBLIC KEY BLOCK` | `pgp-public` |
| `PGP KEY BLOCK` | `pgp` |

### Classification

`class.security-marking` — OFFICIAL, PROTECTED, SECRET, TOP SECRET,
CABINET-IN-CONFIDENCE (opt-in).

## Configuration (code)

Hosts build `PrivacyPolicy` from a privacy profile with `PrivacyProfileLoader.Load`;
custom detectors and secret field names travel on the policy, so
`new JsonEventRedactor(policy)` and `new PrivacyEngine(policy)` include them.
Building a policy in code is for tests and embedding:

```csharp
var defaults = PrivacyPolicy.CreateDefault();
var policy = new PrivacyPolicy
{
    DefaultAction = defaults.DefaultAction,
    DetectorActions = new Dictionary<string, PrivacyAction>(defaults.DetectorActions)
    {
        [DetectorIds.Tfn] = PrivacyAction.Hmac,
        [DetectorIds.Email] = PrivacyAction.Mask,
        [DetectorIds.Abn] = PrivacyAction.Allow
    },
    HmacKey = hmacKey32PlusBytes,
    EnabledOptInDetectors = new HashSet<string> { DetectorIds.IpAddress },
    EmitMetadata = true
};

IEventRedactor redactor = new JsonEventRedactor(policy);
// or
var engine = new PrivacyEngine(policy, customDetectors);
```

## Extension points

0. No code: custom detectors and secret field names in a privacy profile
   ([custom redaction rules](custom-redaction-rules.md)).
1. Implement `ISensitiveDetector` (value scan) and/or `IFieldNameDetector`.
2. Pass detectors into `PrivacyEngine` constructor **or** extend
   `DetectorCatalog.CreateDefaultValueDetectors()`.
3. Set per-id actions / disable flags on `PrivacyPolicy`.
4. Future (not in this milestone): WASM plugins, org-specific learning,
   AI-assisted policy recommendation (config-time only).

## Performance

- Per-event JSON walk; detectors run on string and number leaves and property names.
- Overlapping matches resolved once (prefer longer, then earlier) in O(n log n).
- Replacements applied right-to-left in one pass.
- Micro-benchmarks: `tests/Bower.Benchmarks` (Stopwatch; no extra packages).

## Tests

- Unit tests under `tests/Bower.UnitTests` cover checksums and major detectors.
- Existing `JsonEventRedactor` / `SensitiveDataDetector` tests remain green via
  compatibility facades.

## Related

- [Custom redaction rules](custom-redaction-rules.md) — custom detectors, secret field names, testing
- [Managed privacy profiles](managed-privacy-profiles.md) — versioning, two-person review, signed deployment
- `src/Bower.Redaction/AGENTS.md` — contributor invariants
- `src/Bower.Core/SecurityEventProcessor.cs` — redaction before enqueue
}
