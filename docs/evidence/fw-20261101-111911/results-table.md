| Scenario | Attempt | Sender rsyslog | Native | Queue distinct (missing) | Sentinel distinct (missing) | Sentinel rows at reconciliation / final | Outcome |
|---|---|---|---|---|---|---|---|
| `a-steady` | 1 | 8.2204.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sigkill` | 1 | 8.2204.0 | 6000 | 6000 (0) | 6000 (0) | 6011 / 6011 | PASS: 0 missing; 11 duplicate Sentinel rows, collapse to 6000 |
| `a-reset` | 1 | 8.2204.0 | 1200 | 1200 (0) | 1200 (0) | 1200 / 1200 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sender-reboot` | 1 | 8.2204.0 | 600 | 594 (6) | 594 (6) | 594 / 594 | **FAIL**: 6 missing at the queue, 6 at Sentinel |
| `a-sender-reboot-only` | 1 | 8.2204.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sender-reboot` | 2 | 8.2610.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sender-reboot-only` | 2 | 8.2610.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sigkill` | 2 | 8.2610.0 | 6000 | 6000 (0) | 6000 (0) | 6000 / 6021 | PASS: 0 missing; 21 duplicate Sentinel rows, collapse to 6000 |
| `a-reset` | 2 | 8.2610.0 | 1200 | 1200 (0) | 1200 (0) | 1200 / 1200 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-restart` | 1 | 8.2610.0 | 6000 | 6000 (0) | 6000 (0) | 6000 / 6004 | PASS: 0 missing; 4 duplicate Sentinel rows, collapse to 6000 |
| `a-collector-reboot` | 1 | 8.2610.0 | 3000 | 3000 (0) | 3000 (0) | 3000 / 3000 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-blackhole` | 1 | 8.2610.0 | 1800 | 1800 (0) | 1800 (0) | 1800 / 1800 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-sender-stop-start` | 1 | 8.2610.0 | 1800 | 1800 (0) | 1800 (0) | 1800 / 1800 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-burst` | 1 | 8.2610.0 | 6000 | 6000 (0) | 6000 (0) | 6000 / 6000 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-steady` | 2 | 8.2610.0 | 600 | 600 (0) | 600 (0) | 600 / 600 | PASS (strict: 0 missing, 0 duplicate rows) |
| `b-idle-gaps` | 1 | 8.2610.0 | 6300 | 6300 (0) | 6300 (0) | 6300 / 6300 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-destination-outage-15m` | 1 | 8.2610.0 | 9000 | 9000 (0) | 9000 (0) | 9000 / 9000 | PASS (strict: 0 missing, 0 duplicate rows) |
| `a-capacity-refusal` | 1 | 8.2610.0 | 20000 | 20000 (0) | 20000 (0) | 20000 / 20000 | PASS (strict: 0 missing, 0 duplicate rows) |
