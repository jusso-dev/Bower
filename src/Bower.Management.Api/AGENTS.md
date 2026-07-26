# Bower Management instructions

This directory owns tenant-controlled fleet inventory, enrolment approval,
management audit and Entra ID authorization.

- Enforce every permission in the API; UI checks are not security controls.
- Bind collector records to validated service-principal object IDs.
- Never expose access tokens, secrets, raw event payloads or source credentials.
- Approval, suspension, revocation and role-sensitive changes require audit rows.
- Development authentication must fail closed outside Development.
- Management-plane unavailability must not stop local collection or delivery.
- Add authorization and transaction tests when changing endpoints or state.
