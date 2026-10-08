# Bower Packs

A pack bundles everything Bower needs for one application type, versioned and
signed:

| Content | Purpose |
|---|---|
| `policies/*.yaml` | Default-deny selection for the app's event types |
| `privacy.yaml` (optional) | Privacy profile: detector actions, HMAC field rules, length limits |
| `parsers/*.json` | Custom log parser configurations |
| `detections/*.yml` | Sigma-compatible detections |
| `samples/*.jsonl` | Expected decisions and values that must never survive redaction |
| `dcr/bower-dcr.json` | Generated table and DCR template (`dcr: true`) |

Example: [`packs/linux-ssh-gateway`](../../packs/linux-ssh-gateway).

## Build, sign, verify

```bash
bower keys generate --out-dir ./keys
bower pack build packs/linux-ssh-gateway --key ./keys/bower-signing.key.pem --out ./artifacts/packs
bower pack verify ./artifacts/packs/linux-ssh-gateway-1.0.0.bowerpack --trusted-key ./keys/bower-signing.pub.pem
bower pack test   ./artifacts/packs/linux-ssh-gateway-1.0.0.bowerpack --trusted-key ./keys/bower-signing.pub.pem
bower pack diff   old.bowerpack new.bowerpack --trusted-key ./keys/bower-signing.pub.pem
```

`build` parses and validates every file **and runs every sample**; a pack whose
samples fail cannot be signed. Sample lines:

```json
{"name":"TFN never leaves the host","expect":"accept","mustNotContain":["123456782"],"event":{ … "timeGenerated":"{{now}}" … }}
```

`diff` is the policy population diff: event types added or removed, required fields,
actions and score thresholds, and policies changed without a version bump (exit 1).

## Format

A `.bowerpack` is a zip with `manifest.json` (canonical JSON listing every file with
its SHA-256 and role, the policy ids/versions/hashes and a pack hash),
`manifest.sig` (ECDSA P-256 over the manifest) and `content/…`. Verification fails
on a bad signature, an untrusted key, a modified, missing or unlisted file, path
traversal, more than 500 entries, a file over 1 MiB or an archive over 50 MiB.
Nothing is loaded from an unverified pack.

## Using packs on a collector

```text
BOWER_PACKS=/etc/bower/packs/linux-ssh-gateway-1.0.0.bowerpack
BOWER_PACK_TRUSTED_KEYS=/etc/bower/keys/bower-signing.pub.pem
BOWER_PRIVACY_HMAC_KEY_FILE=/run/secrets/bower-hmac      # if the profile uses hmac
BOWER_PRIVACY_HMAC_KEY_ID=k2026
```

Pack policies are added to the policy directory's; duplicate policy ids fail start-up.
Only one privacy profile may be active (from a pack or `BOWER_PRIVACY_PROFILE`). The
collector reports a **policy bundle hash** (policies, packs and profile) to management,
which compares it with the policy an administrator assigned.
