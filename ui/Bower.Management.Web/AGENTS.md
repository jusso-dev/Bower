# Bower Management Web instructions

This React application is an operational security console, not a generic admin
template.

- Use the canonical Bower tokens in `tokens.css`; no inline colour or font values.
- API authorization is authoritative. UI role checks only guide the interface.
- Never place access tokens, collector secrets or raw telemetry in browser storage.
- Do not invent fleet data, health evidence, approvals or delivery status.
- Preserve keyboard operation, visible focus, reduced motion and 320px support.
- Test loading, empty, error, unauthorized and stale-data states.
