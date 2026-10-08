# Bower.Packs instructions

Signed, versioned bundles of policy, privacy profile, parsers, Sigma detections,
samples and a DCR template for one application type.

- Never load an unsigned pack or a pack signed by an untrusted key. No "skip
  verification" switch.
- Every archive file must be listed in the signed manifest with its SHA-256; unlisted
  files, path traversal and oversized entries fail verification.
- Content is parsed and validated at build time, so a broken pack cannot be signed.
- Privacy profiles never contain keys; hosts supply HMAC keys at load.
- Policy changes in a new pack version need a population diff (`PackDiff`) and a
  version bump for every changed policy.
