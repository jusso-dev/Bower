# Actual source-fault evidence

Each JSON file records the fault that actually executed, separately from exact
native/queue/Sentinel delivery reconciliation. The capture script is retained
byte-for-byte as `capture-sourcefault.sh`; its hash was verified against every
before/after SSM command receipt.

The script is read only. Invoke it through `lab/aws/monitoring/run.py` so account,
exact instance ID, current RunId/Project/Role tags, and running state are checked
before each command. The public environment values are:

| Name | Value |
| --- | --- |
| `BOWER_SCENARIO` | The frozen scenario name |
| `BOWER_FAULT_UNIT` | Exact `bower-lab-f-*` unit from that plan |
| `BOWER_FAULT_ACTION` | The plan's restart, kill, blackhole, reset, reboot or stop-start action |
| `BOWER_CAPTURE_MODE` | `before` or `after` |
| `BOWER_SCOPE_START_EPOCH` | Frozen plan start minus two seconds |
| `BOWER_SCOPE_END_EPOCH` | Expected collection bound before dispatch; actual observation bound afterward |

Capture the baseline before scheduling the fault. Capture again after the
planned workload and fault complete. Keep outputs and command receipts in new,
private files. The script projects timestamps, fault identity, process IDs/start
ticks, boot identity, packet counters and helper hash. It never emits arbitrary
journal messages, bodies or environment values. It retains no raw journal dump.

Qualification checks bind both captures to the same owned instance and installed
helper hash. A restart, kill or stop-start must change the relevant process
identity. Kill additionally names the original PID. Blackhole/reset must show a
positive affected-packet count and the requested elapsed duration. Reboot must
change boot identity and have an in-window reboot marker. The relevant collector
or sender service must be active before and after the fault. Fault start must be
within 15 seconds of its frozen scheduled time. Missing evidence fails these
checks; a scheduling receipt alone never passes.

The final JSON binds the frozen plan and original capture/command receipts by
SHA-256. It carries `deliveryQualified=false` because fault execution alone says
nothing about destination delivery. `summary.json` links each actual fault proof
to the separately reconciled native and Sentinel identity sets. Reproduce those
file checks with the verifier in `../identity-evidence/README.md`.
