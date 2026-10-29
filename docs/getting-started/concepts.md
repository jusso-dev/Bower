# Concepts and glossary

The same plain-English definitions appear in the Bower console's Help page.

## The event path

**Collect → Select → Arrange → Deliver → Prove.** Collect security events, select
what policy allows, structure and redact before persistence, deliver with
acknowledgement, then verify a canary with a destination query.

## Collector {#collector}

The small Bower program on one of your machines. It gathers security events, removes sensitive details and sends the events on.

## Microsoft Sentinel {#sentinel}

Microsoft's security monitoring service. Your security team searches the events Bower sends there.

## Test event {#test-event}

A harmless event Bower sends on purpose and then looks for in Microsoft Sentinel. Finding it proves the whole path works. A simulated test skips that check, so it is not proof.

## Privacy profile {#privacy-profile}

Your rules for which sensitive details Bower removes or masks before anything is stored or sent.

## Event rules {#event-rules}

The approved rules that decide which security events Bower keeps and sends. Everything else is dropped.

## Set aside {#set-aside}

Events Bower could not send after many tries. They are kept, not deleted, so someone can review them.

## Group {#group}

Collectors that share an environment name, such as production or staging. Each group gets one traffic light.

## DCR (data collection rule) {#dcr}

The Azure rule that maps incoming event fields to columns in your Log Analytics table. Choosing a DCR does not prove events have arrived.

## Pack {#pack}

A signed bundle of parsers, event rules and related security content for a particular source. Bower only loads packs signed by a trusted key.

## Policy {#policy}

The approved rules that decide which security events Bower keeps or drops. Unknown events are dropped by default.

## Redaction {#redaction}

Removing or replacing sensitive details before an event is stored or sent. A privacy profile controls these protections.

## Canary {#canary}

A harmless test event used to check the whole path. Only a query that finds that event in Microsoft Sentinel proves delivery; a simulated run does not.

## Default deny

Unknown events are rejected by policy unless an approved rule explicitly allows them.

## Source

The application, host or cloud service that produces a security event.

## Evidence

A record of a test result. Query-verified evidence means Sentinel returned the exact
test event. Simulated evidence is labelled simulated and is not proof of delivery.
