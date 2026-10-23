# Pack runtime event catalogue

`linux-ssh-gateway` 1.1.0 exposes one signed JSON parser (index 0). The source
contract is normalized SSH/PAM JSON, with stable original ID, offset timestamp,
username, source IP and exact result `failure`. It produces only
`authentication_failure`, action `authentication.attempt`, result `failure`,
application `ssh-gateway`, environment `production`. Unknown actions stay denied.

Existing `BWR-PACK-SSH-AUTH` 1.0.0 selects eligible events. The pack privacy profile
pseudonymises usernames before persistence. Local rule
`bower-pack-ssh-auth-failure-001` 1.0.0 attaches stable rule hash/version and T1110
metadata to the accepted semantic row. It does not assert an observed password
spray aggregate; matching is per event. Unmapped raw fields are discarded.

Other parser configurations without a signed runtime mapping are preview-only.
Cloud packs use their existing semantic agent paths and local detections; no new
cloud raw parser is activated here. DCR templates remain packaged-only.

See [activation, limits, failure codes and Sigma subset](../deployment/packs.md#local-parser-and-detection-activation).
All host demonstrations are local and synthetic. Destination delivery requires a
separate authorised query; no Sentinel delivery or all-software coverage is claimed.
