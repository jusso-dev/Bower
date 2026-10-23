# Security policy population change (COV-01, COV-05)

This release adds optional exact, case-sensitive `eventActions`, `eventResults`
and `eventSeverities` predicates. Predicates combine with category/type using AND;
values within one predicate use OR. Omitted predicates preserve old matching and
canonical policy hashes. Empty/null predicates and unknown results/severities fail
loading. Unrecognised event types still fail closed. Upgrade both collector
runtimes before installing policies that use these new keys; older strict loaders
reject them instead of silently accepting broader input.

## Versioned population diff

| Population | Before | After |
|---|---|---|
| Authentication failure / lockout | Accepted with required context | Unchanged |
| Evidence canary / privacy alert | Accepted with required context | Unchanged |
| SDK role add/remove | Default deny | New `BWR-POL-ROLE-MEMBERSHIP` 1.0.0; actor, target, changed role and correlation required |
| SDK sensitive export | Default deny | New `BWR-POL-SENSITIVE-EXPORT` 1.0.0; actor, export ID, classification, count and correlation required |
| Successful generic cloud inventory/read | Accepted by broad cloud category/type | Rejected locally even if upstream subscription broadens |
| Named IAM, logging-control and security configuration changes | Accepted | Retained by explicit action lists; AWS detach-policy and remove-group-member operations added upstream and locally |
| Denied/failed cloud API operations | Accepted | Retained by new denied-operation policies, irrespective of API action |
| Low/informational cloud findings | Accepted | Rejected; medium/high/critical retained |
| Unknown software/event types | Denied | Denied |

AWS and GCP packs and their existing policies move from 1.0.0 to 1.1.0.
New denied-operation policies start at 1.0.0. Exact action populations live in
`packs/*/policies`; there is no suffix wildcard or inferred arbitrary method
support. Source variants need reviewed additions and new fixtures. This is a
class-level fixture population diff, not a measured claim about tenant volume,
coverage or cost. Unknown tenant distributions remain unmeasured.

## Regression evidence

`DefaultSignalCoverageTests` hosts the actual collector with shipped default
policies and explicit single-trust-domain test configuration. All three public
SDK methods must reach its durable queue. It also checks approved cloud actions,
broadened inventory feeds and malformed predicates. Rust `policy_evaluator` and
`policy_loader` tests pin the same selection cases; default policy hash vectors
are generated from C#. Existing policy hashes remain pinned and unchanged.

## Investigation contract

Role changes retain actor, target user, grant/revoke action and approved role
change values. Exports retain actor, export identity, classification, count and
correlation; no exported content is collected. New Sentinel columns append
`TimeObserved`, `EventOutcomeReason`, `Target`, `Change`, and `Attributes` to the
existing schema. DCRs accept only the already-redacted envelope; rich context
never authorises raw request/response forwarding. Destination query validation
of these fields is still required in the intended workspace before release claims.
