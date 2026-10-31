# Collector health trust boundary

Rust collector and Lambda intake quarantine the reserved `collector_health` event
type before policy evaluation or persistence. This applies to semantic HTTP input and
events mapped by signed packs, including syslog. Rust does not emit health records.

This guard protects Bower's intake path only. Sentinel monitoring also relies on
restricting access to the destination ingestion endpoint and table: a principal able
to write directly to the shared destination can forge collector health records without
using Bower. Protect collector identity and destination credentials, scope ingestion
permissions to trusted collectors, and investigate unexpected writers. The guard is
not a cryptographic proof of origin for records already in the destination.
