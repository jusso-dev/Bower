# Security events you can trust

Bower carries useful security events from your systems to Microsoft Sentinel.
It selects the events your policy allows, protects sensitive details before they
are stored, and gives you a way to check that a test event arrived.

You run Bower in your own infrastructure. The console belongs to your tenant.

## What happens to an event?

1. **Collect.** An application or collector produces a security event, such as a failed sign-in.
2. **Select.** Your approved policy decides whether to keep it. Unknown events are denied by default.
3. **Arrange.** Bower structures the event and protects sensitive fields before persistence.
4. **Deliver.** A durable queue and bounded output handle sending and acknowledgement.
5. **Prove.** For a canary, a Sentinel query looks for the exact test event. An evidence bundle records the result. It is signed only when a signing key is configured; otherwise, it is unsigned.

!!! important "Acceptance is not proof"
    A collector accepting an event is one step along the path. Only finding the
    exact test event in Sentinel proves delivery. A simulated run is labelled
    **simulated** and does not prove arrival.

## Pick your next step

- **New to Bower?** Follow [your first verified event](first-event.md).
- **Planning an installation?** [Choose a deployment](deployment.md).
- **Already using the console?** Find the [dashboard guides](../guides/index.md).
- **Looking after an existing installation?** Use the [operations guides](../operations/index.md).

Bower is a security telemetry bridge. It is not a general log shipper, a SIEM,
an application performance monitor or a replacement for Azure Monitor Agent.
