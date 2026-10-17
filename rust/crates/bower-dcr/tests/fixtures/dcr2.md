# DCR Assessment: arm

- DCR id: `arm`
- Coverage score: **70**
- Health score: **73**

## Recommendations
- **[medium] Missing high-value Windows Event IDs** (missing-security-event-ids): Consider collecting Event IDs: 4624, 4625, 4648, 4672, 4688, 4720, 4728, 4732, 1102.
- **[medium] Incomplete Sysmon Event IDs** (incomplete-sysmon): Ensure Sysmon Event IDs 1, 3, 11 are collected.
- **[medium] Disabled or missing Defender telemetry** (missing-defender): Enable Defender / XDR connector or collect Defender operational channels.
- **[low] Missing IIS logs** (missing-iis): If web workloads exist, collect IIS W3C logs with path filters.
