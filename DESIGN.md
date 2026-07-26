# Bower interface design

## Direction

Bower Management is a restrained operational workbench for security operators,
platform administrators, approvers and auditors. It is exception-led: pending
identity, stale source, queue pressure and failed delivery appear before passive
inventory.

## Visual system

- Custom Bower palette in OKLCH: satin blue, charcoal, slate, muted ochre.
- Geist for operational reading; IBM Plex Mono for identifiers and evidence.
- Light operational canvas plus deliberate dark mode.
- Hairline containment, compact tables, one side rail, no decorative card wall.
- Abstract signal convergence mark; no cartoon bird or ornamental telemetry art.

## Interaction

- Mobile-first at 320, 375, 414 and 768 CSS pixels.
- Desktop side rail becomes a direct mobile navigation sheet.
- Visible focus, 44px targets, no colour-only state and reduced-motion support.
- Loading skeletons, contextual empty states and explicit errors.
- Successful visible actions are silent; approval history is the durable feedback.

## Authorization

UI role checks guide affordances only. The ASP.NET Core API validates Entra
issuer, audience, lifetime, signature and `roles`, then enforces policies.
Collectors use a separate application role and are bound to their service
principal object ID.
