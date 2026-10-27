# Console home view

Issue #98, epic #115. The console opens on **Home** (`/`). It answers three questions
for an owner who does not read CLI output:

1. Is my data flowing?
2. What was protected (redacted) this week?
3. What needs my attention?

The detailed fleet view is still one click away at **Overview** (`/overview`). Home is
part of the same console, sign-in and audit trail. It changes nothing: every action
links to the page (and role) that already performs it, so approvals and four-eyes
rules are unchanged.

## Where the answers come from

`GET /api/home` (any interactive role: `Bower.Viewer` and up) computes the whole view
on the server at request time. The browser only renders it. Inputs:

| Input | Source |
|---|---|
| Collector state | The management store: lifecycle status, last heartbeat, delivery status, dead letters, oldest undelivered age, per-source status, policy and privacy profile drift |
| Connectivity | Heartbeat v2 states (`online`, `stale`, `unhealthy`, `offline`), see [heartbeat v2](../architecture/heartbeat-v2.md) |
| Sentinel proof | Setup canary runs from the [onboarding wizard](console-onboarding.md) |
| Redaction counts | The `redactions` field of the collector heartbeat (below) |

Every sentence and fix is fixed Bower text with counts filled in. Nothing a collector
sends reaches the page except counts, detector type ids (shown as plain-English names)
and the environment name used as the group name.

## Is my data flowing?

A collector is **sending** when it is approved, `online`, and its delivery status is
operational (the same set the Overview uses). Revoked collectors are ignored.

| Answer | Light | When |
|---|---|---|
| Yes | green | Every running collector is sending |
| Partly | amber | Some are sending |
| No | red | None are sending, or every collector is paused |
| Not yet | amber | No collector is approved yet |

**Last accepted for sending** is the latest output acceptance a collector reported. It
is not proof of arrival, and the page says so.

**Sentinel proof** follows the evidence rules:

- `verified`: the latest setup test event that Bower found by querying the workspace.
  Shown as "Proven" with its time. An older verified run stays the proof even if a
  later run was simulated.
- `simulated`: no verified run exists and the latest run did not query Sentinel. Always
  labelled "Simulated only ... not proof".
- `not-proven`: no run, or the latest run failed.
- `in-progress`: a run is checking Sentinel now.

`simulated` and `not-proven` also appear under "What needs my attention?" with the fix
"Send a test event from the Setup page".

## What needs my attention? and collector groups

Collectors are grouped by environment. Each group takes the state and reason of its
worst condition, in this order:

| Id | Light | Reason (for example) | Fix page |
|---|---|---|---|
| `offline` | red | 1 of 3 collectors has not checked in for more than 15 minutes. | Collectors |
| `history-changed` | red | ... reported an event history that changed unexpectedly. | Audit |
| `not-sending` | red | ... not been able to send events for more than 15 minutes. | Collectors |
| `stale` | amber | ... not checked in for a few minutes. | Collectors |
| `send-trouble` | amber | ... had trouble sending events. | Collectors |
| `pending` | amber | ... asked to join. | Approvals |
| `suspended` | amber | ... been paused. | Collectors |
| `set-aside` | amber | ... events that could not be sent and were set aside. | Collectors |
| `backlog` | amber | ... events waiting more than 15 minutes to be sent. | Collectors |
| `quiet-source` | amber | ... an expected app that has gone quiet. | Collectors |
| `policy-not-applied` | amber | ... not switched to the assigned event rules yet. | Collectors |
| `privacy-not-applied` | amber | ... not applied its assigned privacy profile yet. | Privacy profiles |

A group with none of these is green: "All 3 collectors are checking in and sending
events." Every amber or red reason carries a fix: what to do and a link to the page.
The attention list counts each condition across the fleet, worst first, and adds
`no-collectors`, `not-proven` and `simulated` where they apply. The overall light is
the worst of the flow answer and the attention list. At most 50 groups are returned,
most urgent first, with the total.

## What was protected this week?

Collectors count, per detector type, the queued events in which Bower removed or masked
at least one value. Counts are by type only. Values, field paths and event ids are never
counted, sent or shown.

- A type is the detector id before any `:` sub-kind (`secret.aws:access-key` counts as
  `secret.aws`). Each type counts once per event.
- Only events that were stored count. A duplicate retry, a suppressed event, a rejected
  event and Bower's own privacy alert add nothing.
- A collector counts at most 64 types; later new types count as `other`.
- Counters live in memory and start again when the collector restarts. Each heartbeat
  reports the running totals with `observedSince` (the process start).

Management turns each report into the increase since the last one for the same
`observedSince` (a later start counts from zero) and adds it to a per-collector,
per-day (UTC) bucket. A report from an earlier start than one already accepted is
ignored, and within one start a lower total adds nothing, so a late or replayed report
is never counted twice. A heartbeat without `redactions` marks the collector as not
reporting; its earlier counts stay. Buckets are kept for 35 days. "This week" is
today (UTC) and the six days before it. Counts between a collector's last heartbeat and
a crash are lost, so the totals are a floor.

The home view groups types into plain names: "Tax file numbers", "Email addresses",
"Phone numbers" (Australian and international), "Passwords, keys and access tokens"
(every `secret.*`, `field-name-secret` and `crypto.material`), "Matches for your own
privacy rules" (every `custom.*`), and "Other sensitive details" for anything else.
Collectors on an older version do not send counts. The page says how many working
collectors that is.

### Heartbeat field

Additive to v1 and v2 heartbeats; older APIs ignore it.

```json
"redactions": {
  "observedSince": "2026-10-27T00:00:00.0000000+00:00",
  "counts": [{ "type": "au.tfn", "events": 12 }]
}
```

Management rejects the heartbeat (HTTP 400) when `counts` has more than 64 entries, a
repeated type, a type that is not 1 to 128 lowercase letters, digits, dots or hyphens
(starting with a letter), or a count outside 0 to 10^12.

## Words and help

Glossary terms on the home view ("collector", "Microsoft Sentinel", "test event",
"privacy profile", "event rules", "set aside") link to **Help** (`/help`), which ships
with the console. There are no third-party help or analytics scripts.

## Performance

The view is one request. `HomeApiTests.Home_LoadsUnderTwoSecondsForFiveHundredCollectors`
seeds 500 collectors in 20 groups and checks the request takes less than 2 seconds.
The page refreshes in place every 60 seconds. A failed refresh keeps the last answer
and says when it was computed.
