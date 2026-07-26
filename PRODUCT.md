# Bower Product

## Register

product

## Users

Bower serves security operators, platform administrators, telemetry approvers and
read-only auditors in enterprise, Australian government, managed security,
detection engineering and software delivery teams.

Operators need a trustworthy fleet view showing which collectors and machines are
active, which sources they cover, whether delivery is healthy and where policy or
configuration has drifted. Approvers need a clear separation-of-duties workflow
for collector enrolment and sensitive operational changes. Auditors need
read-only, exportable evidence of identity, approval and state transitions.

## Product Purpose

Bower is a tenant-controlled security telemetry collection and developer
enablement platform for applications Microsoft Sentinel cannot see directly.

Its management surface inventories deployed Bower Collectors and their machines,
records source and output coverage, exposes delivery health, supports explicit
enrolment approval and makes every administrative decision auditable. Collector
delivery must continue when the optional management plane is unavailable.

Primary workflow:

1. A collector requests enrolment using a bounded, one-time bootstrap mechanism.
2. An authorised approver reviews machine identity, environment, collector
   version, requested sources and destination.
3. The approver approves or rejects with a reason.
4. Approved collectors send authenticated heartbeats and coverage summaries.
5. Operators investigate offline collectors, source gaps, policy drift, queue
   pressure and destination failures.
6. Auditors review immutable decision and RBAC history.

## Brand Personality

Technical, austere and deliberate. Calm authority without ornament. Restrained
enterprise identity inspired by the satin bowerbird: deep blue, charcoal, slate
and limited natural accents. Suitable for government and regulated security
operations.

## Anti-references

- Cartoon birds, playful security mascots or literal nest imagery.
- Generic neon-on-black cybersecurity dashboards.
- Decorative gradients, glassmorphism and glow-heavy SOC screens.
- Walls of identical metric cards without operational hierarchy.
- Hidden state transitions, ambiguous approval actions or optimistic claims.
- Consumer-social patterns, gamification or celebratory administrative feedback.
- UI-only security controls that are not enforced by the API.

## Design Principles

1. Show evidence, not reassurance. Every status links to its source and time.
2. Make approval boundaries explicit. Actor, reason and resulting state remain
   visible before and after decisions.
3. Optimise for operational scanning. Exceptions and drift outrank vanity totals.
4. Preserve collector independence. Management outage cannot stop local
   collection, queueing or delivery.
5. Use familiar enterprise affordances. Novelty must never obscure security state.

## Accessibility & Inclusion

Target WCAG 2.2 AA. Support keyboard-only operation, visible focus, reduced
motion, screen-reader names, semantic tables, non-colour status cues, high
contrast and responsive layouts at 320, 375, 414 and 768 pixels.

## Identity and Authorisation

Interactive access uses Microsoft Entra ID SSO.

Application roles:

- `Bower.Viewer`: read fleet, coverage, health and audit records.
- `Bower.Operator`: Viewer access plus operational actions that do not approve
  trust or change RBAC.
- `Bower.Approver`: Viewer access plus collector enrolment and controlled-change
  approval or rejection.
- `Bower.Administrator`: full configuration, role mapping and emergency
  suspension; approval actions remain separately audited.

Entra groups are assigned to these application roles. API authorisation uses
validated app-role claims rather than expanding group membership itself. This
keeps permissions explicit and avoids group-claim overage behavior. Direct user
assignment remains possible for break-glass administration and must be audited.
