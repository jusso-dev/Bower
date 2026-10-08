# Bower.Integrity instructions

Signing and canonicalisation shared by packs and evidence bundles.

- ECDSA P-256 with SHA-256 only. Reject other curves and algorithms.
- Verification trusts only explicitly supplied public keys, matched by key id.
- Canonical JSON must stay byte-stable: sorted keys, no whitespace. Any change is a
  breaking change for every signed artefact.
- Never log or persist private keys.
