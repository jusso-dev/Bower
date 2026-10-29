# Security is part of the path

Bower's protection model is built into collection, selection, persistence and
delivery. These are product invariants, not optional dashboard settings.

- **Default deny.** Unknown event types do not pass policy evaluation.
- **Protect before storing.** Redaction happens before persistence, and failure is handled as a security failure.
- **Trust signed content.** Packs must be signed by a trusted key.
- **Keep acknowledgement state.** Events are not removed before acknowledgement.
- **Prove arrival.** Only a destination query finding the exact event counts as delivery proof.

## Understand the boundaries

Read the [threat model](threat-model.md) for the data flows and assumptions, the
[identity and role model](management-identity-and-rbac.md) for management access,
and [producer scopes](producer-scopes.md) for intake permissions.

The [ISM alignment](ism-alignment.md) document maps controls and evidence. It is not
certification or a statement that a particular deployment is compliant.

## Privacy controls

The [Privacy & Secret Protection Engine](../privacy/privacy-secret-engine.md)
explains detectors, actions and metadata. Use [managed profiles](../privacy/managed-privacy-profiles.md)
and the [guided privacy editor](../operations/console-privacy-editor.md) to review changes.
