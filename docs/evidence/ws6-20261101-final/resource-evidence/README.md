# Retained resource samples

The Linux `final-hour-outage` files are unchanged exports from the owned host:

- `linux-final-hour-outage-scope.json` binds run, plan, boot and sampler worker hash.
- `linux-final-hour-outage-samples.jsonl` contains the full 361-sample, 90-minute series.
- `linux-final-hour-outage-export-summary.json` records completeness and aggregate metrics.

The samples contain process, disk, queue-count and source-counter metadata only.
They contain no queue event bodies, event XML, secrets or credentials. Source
frames and admissions increased by exactly 36,000. The peak pending count also
includes collector health events; it is not an alternative measured event count.
Initial and final pending count were zero. The sampler retained the same boot
and process throughout this series. All subsequent fault tests began after its
final sample and verified export.

The Windows `windows-final-hour-outage-*` files retain all 301 samples from the
75-minute outage/recovery observation. Reads and admissions increased by 36,100:
36,000 measured events and 100 separately identified warmup events. It retained
the same boot and process, with no sample failures or source counter resets,
zero dead letters, and initial/final pending counts of zero. Final readiness was
healthy. Its files were independently checked against export sizes and hashes
before subsequent Windows fault testing.

These measurements support capacity and recovery assessment. Exact delivery is
established separately by the retained native/queue/Sentinel identity proof.

Run this from `docs/evidence/ws6-20261101-final` to verify the original file sizes,
SHA-256 receipts, sample sequence and unchanged boot/process:

```sh
python3 - <<'PY'
import hashlib
import json
from pathlib import Path
root = Path.cwd().resolve()
summary = json.loads((root / 'summary.json').read_text())
phase = summary['resourceSampling']['linuxFinalHourOutage']
for record in phase['artifacts']:
    path = (root / record['file']).resolve()
    assert root in path.parents
    data = path.read_bytes()
    assert len(data) == record['bytes']
    assert hashlib.sha256(data).hexdigest() == record['sha256']
rows = [json.loads(line) for line in (root / 'resource-evidence/linux-final-hour-outage-samples.jsonl').read_text().splitlines()]
assert len(rows) == 361
assert all(row['sequence'] == i and row['metricsAvailable'] for i, row in enumerate(rows))
assert len({row['bootId'] for row in rows}) == 1
assert len({(row['process']['pid'], row['process']['startTicks']) for row in rows}) == 1
assert rows[0]['queue']['pending'] == rows[-1]['queue']['pending'] == 0
for field in ('framesReceived', 'queued'):
    assert rows[-1]['sourceCounters'][field] - rows[0]['sourceCounters'][field] == 36000
assert phase['samplingComplete'] and phase['failedSampleCount'] == 0
print('Verified 361 unchanged source metric samples; delivery proof remains separate.')
phase = summary['resourceSampling']['windowsFinalHourOutage']
for record in phase['artifacts']:
    path = (root / record['file']).resolve()
    assert root in path.parents
    data = path.read_bytes()
    assert len(data) == record['bytes']
    assert hashlib.sha256(data).hexdigest() == record['sha256']
rows = [json.loads(line) for line in (root / 'resource-evidence/windows-final-hour-outage-samples.jsonl').read_text().splitlines()]
assert len(rows) == 301
assert all(row['sequence'] == i and row['metricsAvailable'] for i, row in enumerate(rows))
assert len({row['bootId'] for row in rows}) == 1
assert len({(row['process']['pid'], row['process']['startTicks']) for row in rows}) == 1
assert rows[0]['queue']['pending'] == rows[-1]['queue']['pending'] == 0
assert rows[-1]['healthOk']
assert all(row['queue']['deadLettered'] == 0 for row in rows)
for field in ('eventsRead', 'queued'):
    assert rows[-1]['sourceCounters'][field] - rows[0]['sourceCounters'][field] == 36100
for field in set(rows[0]['sourceCounters']) - {'eventsRead', 'queued'}:
    assert all(row['sourceCounters'][field] == 0 for row in rows)
assert phase['samplingComplete'] and phase['failedSampleCount'] == 0
print('Verified 301 unchanged Windows metric samples, including 100 warmup events.')
PY
```
