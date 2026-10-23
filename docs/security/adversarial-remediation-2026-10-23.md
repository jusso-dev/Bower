# Adversarial remediation tracker

Baseline: `473c6ec6ffb9c195d49c54caae1267bd069c548f`. Implementation in progress. Each finding needs regression evidence; baseline green tests do not close findings. No live tenant delivery proven.

| Finding | Scope | State |
|---|---|---|
| AZ-01 | Concurrent Azure uploads acknowledge the failed event and reject a different event | Open |
| AZ-02 | Current Sentinel schema still omits target, change and event-specific context | Open |
| AZ-03 | Identity or DCR configuration failures dead-letter valid records | Open |
| SEC-01 | Secrets survive change values and request URLs | Open |
| SEC-02 | Documented management Entra audience mismatches v2 tokens | Open |
| SEC-05 | Producer authentication does not authorize application or tenant identity | Open |
| DUR-01 | SDK reports dropped events as accepted and hides sender failure | Open |
| DUR-02 | Fingerprint merges distinct security events | Open |
| DUR-03 | SQL timestamp cursor stalls on a saturated timestamp | Open |
| COV-01 | Defaults reject role-change and export SDK events | Open |
| COV-02 | Cloud mappings lose permission-change investigation context | Open |
| AZ-04 | Final Retry-After is lost when SDK-level retries exhaust | Open |
| AZ-05 | Evidence control mappings claim more than canary query establishes | Open |
| AZ-06 | Entra ingestion is implemented but provisioning remains partly manual | Open |
| SEC-03 | Unchecked heartbeat counts persistently crash fleet overview | Open |
| SEC-04 | Revoked collectors can rewrite protected inventory | Open |
| DUR-04 | Conflicting event ID returns duplicate success | Open |
| DUR-05 | Stale worker can settle a newer lease | Open |
| DUR-06 | Legitimate replay after retention reports false ledger corruption | Open |
| DUR-07 | Unresolved event pins unbounded ledger history | Open |
| DUR-08 | Delivery health reports healthy when output disabled or stalled | Open |
| COV-03 | Signed pack parser/detection assets never activate in collector | Open |
| COV-04 | Sigma subset silently changes Boolean and equality semantics | Open |
| COV-05 | High-value filtering relies on upstream subscription remaining narrow | Open |
| OPS-01 | SQL size checks follow unrestricted row allocation | Open |
| OPS-02 | UI token cache contradicts repository security requirement | Open |

Release gates: byte-level privacy; exact event acknowledgement; outage storage/backpressure; populated database migration and recovery; source/policy/DCR field preservation; supported parser/detection activation; independent destination query. Unsupported evidence dimensions remain not-assessed.
