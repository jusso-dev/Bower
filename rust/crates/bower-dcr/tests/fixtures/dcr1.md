# DCR Assessment: servers

- DCR id: `dcr-1`
- Coverage score: **40**
- Health score: **35**
- Current monthly ingestion: **123.46 GB**
- Estimated monthly savings: **37.04 GB**

## Recommendations
- **[medium] Duplicate collection sources** (duplicate-source): Data source name 'windows-security' appears 2 times.
- **[high] Replace Security Event * with targeted Event IDs** (broad-security-events): Broad Security channel collection inflates ingestion. Prefer targeted Event IDs.
- **[medium] Missing high-value Windows Event IDs** (missing-security-event-ids): Consider collecting Event IDs: 4624, 4625, 4648, 4672, 4688, 4720, 4728, 4732, 1102.
- **[high] Missing Sysmon configuration** (missing-sysmon): Collect Sysmon Event IDs 1, 3 and 11 for process, network and file visibility.
- **[medium] Disabled or missing Defender telemetry** (missing-defender): Enable Defender / XDR connector or collect Defender operational channels.
- **[low] Missing IIS logs** (missing-iis): If web workloads exist, collect IIS W3C logs with path filters.
- **[medium] Disabled data sources present** (disabled-sources): Review disabled sources for accidental coverage gaps or stale configuration.
