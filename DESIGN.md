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

## Guided flows

Plain-language views for non-technical owners (the `/setup` wizard first, then the
home view, guided source setup and help) share the primitives in
`ui/Bower.Management.Web/src/components/guided.tsx`:

- `Stepper`: an ordered `nav` list of buttons. Every step stays selectable so a
  finished flow can be revisited; the current step has `aria-current="step"` and each
  button's name is "Step N: title, status".
- `GuidedStep`: one step's panel with "Step N of M", the title and a status. Focus moves
  to its heading when the step changes, never on first render.
- `PlainStatus`: "Done", "Needs attention", "Waiting on earlier steps", "In progress",
  "Not started", always words plus an icon shape. A label can change the words (for
  example "Verified in Sentinel") but never the tone.
- `CheckList`: validation results; every result that does not pass shows "How to fix".
- `WhyItMatters`: the one-line reason for a step.
- `TrafficLight`: "All good", "Needs a look" or "Needs action now" (green, amber, red),
  always words plus an icon shape. The home view uses it for the flow answer, each
  attention item and each collector group.
- `GlossaryText` (`components/glossary.tsx`): links the first mention of each glossary
  term in a sentence to its entry on the Help page (`/help#<term>`). Server sentences
  stay plain text; nothing is parsed as markup.

The home view (`/`) answers "Is my data flowing?", "What was protected this week?" and
"What needs my attention?" from `/api/home`. Every amber or red reason ends in "How to
fix:" with a link to the page that does it; the detailed Overview is at `/overview`.

Copy is plain English, leads with the point and names the role or page that acts. The
API authors check messages and fixes, so the console never shows raw Azure or framework
errors. Progress lives on the server, never in browser storage. Proof wording follows
the evidence rules: acceptance is never "delivered", and simulated always says so.

## Authorization

UI role checks guide affordances only. The ASP.NET Core API validates Entra
issuer, audience, lifetime, signature and `roles`, then enforces policies.
Collectors use a separate application role and are bound to their service
principal object ID.
