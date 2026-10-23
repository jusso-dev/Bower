# Adversarial remediation tracker

Baseline: `473c6ec6ffb9c195d49c54caae1267bd069c548f`. Implementation in progress. Each finding needs regression evidence; baseline green tests do not close findings. No live tenant delivery proven.

| Finding | Scope | State |
|---|---|---|
| AZ-01 | Concurrent Azure uploads acknowledge the failed event and reject a different event | Implemented; final combined gates pending |
| AZ-02 | Current Sentinel schema still omits target, change and event-specific context | Implemented; final combined gates pending |
| AZ-03 | Identity or DCR configuration failures dead-letter valid records | Implemented; final combined gates pending |
| SEC-01 | Secrets survive change values and request URLs | Implemented; final combined gates pending |
| SEC-02 | Documented management Entra audience mismatches v2 tokens | Implemented; final combined gates pending |
| SEC-05 | Producer authentication does not authorize application or tenant identity | Implemented; final combined gates pending |
| DUR-01 | SDK reports dropped events as accepted and hides sender failure | Implemented; final combined gates pending |
| DUR-02 | Fingerprint merges distinct security events | Scoped implementation running |
| DUR-03 | SQL timestamp cursor stalls on a saturated timestamp | Scoped implementation running |
| COV-01 | Defaults reject role-change and export SDK events | Implemented; final combined gates pending |
| COV-02 | Cloud mappings lose permission-change investigation context | Scoped implementation running |
| AZ-04 | Final Retry-After is lost when SDK-level retries exhaust | Implemented; final combined gates pending |
| AZ-05 | Evidence control mappings claim more than canary query establishes | Implemented; final combined gates pending |
| AZ-06 | Entra ingestion is implemented but provisioning remains partly manual | Implemented; final combined gates pending |
| SEC-03 | Unchecked heartbeat counts persistently crash fleet overview | Implemented; final combined gates pending |
| SEC-04 | Revoked collectors can rewrite protected inventory | Implemented; final combined gates pending |
| DUR-04 | Conflicting event ID returns duplicate success | Scoped implementation running |
| DUR-05 | Stale worker can settle a newer lease | Scoped implementation running |
| DUR-06 | Legitimate replay after retention reports false ledger corruption | Scoped implementation running |
| DUR-07 | Unresolved event pins unbounded ledger history | Scoped implementation running |
| DUR-08 | Delivery health reports healthy when output disabled or stalled | Implemented; final combined gates pending |
| COV-03 | Signed pack parser/detection assets never activate in collector | Scoped implementation running |
| COV-04 | Sigma subset silently changes Boolean and equality semantics | Scoped implementation running |
| COV-05 | High-value filtering relies on upstream subscription remaining narrow | Implemented; final combined gates pending |
| OPS-01 | SQL size checks follow unrestricted row allocation | Scoped implementation running |
| OPS-02 | UI token cache contradicts repository security requirement | Implemented; final combined gates pending |

Release gates: byte-level privacy; exact event acknowledgement; outage storage/backpressure; populated database migration and recovery; source/policy/DCR field preservation; supported parser/detection activation; independent destination query. Unsupported evidence dimensions remain not-assessed.
