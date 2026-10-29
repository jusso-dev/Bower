# Frequently asked questions

## Is Bower a SIEM?

No. Bower is a self-hosted security telemetry bridge. It delivers useful, protected
security signal to destinations such as Microsoft Sentinel. It does not replace
Sentinel, application monitoring or general-purpose logging.

## Does Bower send everything?

No. Policy evaluation is deterministic and denies unknown events by default. Packs
and policies define which security events are understood and allowed.

## When are sensitive details removed?

Before persistence. A redaction failure is treated as a security failure, not a
reason to store the original event. Read the [privacy engine guide](../privacy/privacy-secret-engine.md).

## Why does my test say simulated?

A simulated run did not perform the destination query needed for delivery proof.
Configure the read-only Sentinel verifier and run the canary again. See
[your first verified event](first-event.md).

## Is a healthy collector proof of delivery?

No. A heartbeat reports collector state. Even an accepted output request does not
prove the exact event can be queried in Sentinel. Use a query-verified canary.

## Can I change settings with viewing access?

No. The simplified console changes navigation, not permissions. The API enforces
roles. Ask an authorised operator, approver or administrator for the action you need.

## Do these docs track me?

No analytics or external help widgets are included. Search runs locally in your
browser. Fonts and scripts are served with the site. GitHub Pages hosts the static
files and has its own service-level logging.
