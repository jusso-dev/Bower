# Privacy & Secret Protection Engine

Bower's privacy engine inspects every event **after parse and before
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
| Fail closed | Invalid / oversized payloads, duplicate keys and detector timeouts → redaction failure → quarantine |
| Complete coverage | String **and number** values are scanned, and so are **property names** |

## Actions

| Action | Effect |
| --- | --- |
| `Allow` | Leave value unchanged (still recorded in metadata if detected) |
| `Remove` | Delete property (field-name) or replace span with empty |
| `Replace` | Replace with configured placeholder |
| `Mask` | Partial reveal (e.g. last 4 digits, email local-part) |
| `Sha256` | `sha256:<hex>` |
| `Hmac` | `hmac-sha256:<hex>`; requires a 32+ byte key. The engine refuses to start if `Hmac` is configured without one |
| `Encrypt` | AES-GCM (`enc:aesgcm:…`); requires 32-byte key; else remove |
| `AlertOnly` | Detect only; do not rewrite |

## Default policy (production-oriented)

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

A YAML profile changes detector actions and adds field rules
(`BOWER_PRIVACY_PROFILE`, or inside a signed pack):

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
without a key fails at start-up. Unknown detector ids, actions or keys fail the load.

`maximumFieldLength` keeps values below the Logs Ingestion API's silent 64 KB
truncation, so Bower decides where a value is cut and records it as
`limit.field-length` in privacy metadata.

### Numbers and key names

Detectors run over the exact JSON text of numbers, so a card number or TFN sent
as a number (`"card": 4111111111111111`) is caught. A redacted number becomes a
string. Property names are scanned too: a sensitive key is renamed to its
redacted form (for example `a***@example.test`) or to `redacted-key-N` when the
action removes it.

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

## Detector modules

### Australian identifiers

| Id | Validation |
| --- | --- |
| `au.tfn` | ATO 8/9-digit checksum |
| `au.crn` | Pattern (9 digits + letter) |
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

### Identity

`id.email`, `id.phone.au`, `id.phone.intl`, `id.dob`, plus optional
`id.address`, `id.gps`, `id.ip`, `id.hostname`, `id.username`.

### Secrets & crypto

AWS, Azure, Entra, GCP, JWT, OAuth, provider API keys (OpenAI, Anthropic,
GitHub, GitLab, Slack, Stripe, Twilio, Cloudflare, Atlassian, Datadog,
PagerDuty, Okta, MongoDB, Snowflake), Kubernetes, Docker, database connection
strings, environment variable assignments, PEM/PKCS8/SSH/PGP/X.509.

### Classification

`class.security-marking` — OFFICIAL, PROTECTED, SECRET, TOP SECRET,
CABINET-IN-CONFIDENCE (opt-in).

## Configuration (code)

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

1. Implement `ISensitiveDetector` (value scan) and/or `IFieldNameDetector`.
2. Pass detectors into `PrivacyEngine` constructor **or** extend
   `DetectorCatalog.CreateDefaultValueDetectors()`.
3. Set per-id actions / disable flags on `PrivacyPolicy`.
4. Future (not in this milestone): WASM plugins, org-specific learning,
   AI-assisted policy recommendation (config-time only).

## Performance

- Per-event JSON walk; detectors only run on string leaves.
- Overlapping matches resolved once (prefer longer, then earlier).
- Replacements applied right-to-left.
- Micro-benchmarks: `tests/Bower.Benchmarks` (Stopwatch; no extra packages).

## Tests

- Unit tests under `tests/Bower.UnitTests` cover checksums and major detectors.
- Existing `JsonEventRedactor` / `SensitiveDataDetector` tests remain green via
  compatibility facades.

## Related

- `src/Bower.Redaction/AGENTS.md` — contributor invariants
- `src/Bower.Core/SecurityEventProcessor.cs` — redaction before enqueue
}
