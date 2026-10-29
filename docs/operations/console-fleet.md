# Check your collectors

Open **Collectors** to see which machines need attention. Each machine has one
plain-language state, a short explanation and a suggested action when something
needs fixing. The most urgent machines appear first.

Use **State** and **Site** to narrow the list, or search by machine name or collector
ID. Site means the environment recorded when the collector joined. Filters are
kept in the page URL so you can bookmark a view. **Clear filters** shows the fleet
again. **View details** opens the machine's sources, destinations, queue and policy
status without changing anything.

## What the states mean

| State | What to do |
| --- | --- |
| Healthy | No problems were reported in the recent check-in. No action is needed. |
| Behind a relay | This machine is configured to send through a relay. If delivery fails, check both machines. |
| Waiting for approval | An approver reviews the request on **Approvals**. |
| Not heard from recently | Check that the machine is running and can reach Bower. If its sign-in credential expired or was revoked, enrol it again. |
| Can't deliver to Sentinel | Follow the suggested connection or queue check. Events waiting or set aside need attention even if the machine is still checking in. |
| Running old version | Compare its installed version with your fleet's newest reported stable release and update as appropriate. |
| Needs a check | Follow the specific privacy, policy, source or event-history check shown. |
| Paused | Ask an administrator why management access is paused. Local collection and delivery may continue. |
| Removed | The machine has been revoked and cannot connect to management. |

The page refreshes once a minute. **Refresh** checks immediately. If the request
fails, the last successful snapshot stays visible with an out-of-date warning.
Each machine also shows its last check-in time. A green state is a report of health,
not proof that an event arrived in Sentinel. Use **Check arrival in Microsoft
Sentinel** to open the [setup test](console-onboarding.md).

All interactive roles, including Viewer, can read the fleet and machine details.
Links to Approvals or Enrolment do not grant permission to make changes. Those
pages and their APIs enforce their own roles.

## How the view is calculated

`GET /api/fleet` and `GET /api/fleet/{id}` require the management API's View policy.
They read existing collector records, heartbeat v2 and credential metadata. There
is no new stored collector state and these reads perform no mutations.

The server uses the same condition catalogue as Home, worst first. Additional
conditions are counted, while the machine details retain the reported source,
queue and policy metadata. Version comparisons use valid semantic version cores;
only stable releases from recently connected, approved machines establish the
baseline. A preview release or stale machine cannot make a production release
appear outdated. A v1 heartbeat is also flagged as old because it lacks signed
command support. Builds with unrecognised version strings are not compared.

State labels, explanations, fixes and navigation destinations are fixed Bower
text. No event bodies, source credentials or credential values are returned.
Collector identity and health metadata stay inside the existing authenticated
management boundary; browsers do not persist it.

The offline-site state and last signed-import date depend on air-gapped bundle
imports (#111). They are not manufactured from a missing heartbeat. Issue #113
remains open until that integration is implemented and tested.
