# Sanitized identity evidence

These files preserve exact reconciliation inputs and queried destination rows
without embedding thousands of rows in the summary. They contain synthetic
`winevt-` and `a13-n…x…` identities, copy counts and timestamps. They contain no
event XML, event payloads or tokens.

For each qualified Windows phase, the native, WEC and queue identity files had
identical byte hashes. One unchanged `*-source.ids` file is retained, and
`summary.json` records all three original hashes as an explicit equality
attestation. Separate `*-warmup-source.ids` files preserve the 100-event
preparation sets; the verifier checked that these do not overlap measured
identities. Failed steady and burst source files are retained too. Their export
does not change the failed outcomes in the summary.

Firewall expected identities are derived from the frozen `nft:A:first:count`
plan blocks. Native proof is the generation plan plus the nftables packet-counter
delta; it is not a byte-identical native identity file. Separate expected,
queue and Sentinel files retain the identity sets used for reconciliation.
The summary records native counters, frozen blocks, source evidence hashes and
query provenance. Queue rows contain three columns: `EventId`, `GeneratedAt`,
`ReceivedAt`.

`*-sentinel-identities.jsonl` contains one JSON array per independently queried
identity. Column order is fixed and also recorded beside each file's SHA-256:

| Index | Column | Meaning |
| --- | --- | --- |
| 0 | EventId | Synthetic source identity |
| 1 | Copies | Number of destination rows for that identity |
| 2 | FirstGenerated | Earliest event-generation time |
| 3 | LastGenerated | Latest event-generation time |
| 4 | FirstIngested | Earliest Sentinel ingestion time |
| 5 | LastIngested | Latest Sentinel ingestion time |

Original timestamp strings, including seven fractional digits where returned,
are preserved. File hashes include their actual trailing newlines. Identity-set
hashes use sorted identities joined by `\n`, without a final newline. The
1,000-event Windows diagnostic is separate from the complete 6,000-event burst.
The firewall outage files establish exact delivery after manual restoration;
the automatic guard failed. Overall qualification remains incomplete; final
session cleanup is recorded separately in `summary.json`. Failed source-fault sidecars retain the full expected, queue,
destination and missing identity sets. SIGKILL lost 21 of 6,000 native identities
before durable admission; TCP reset lost 4 of 1,200, and the combined collector
stop/sender reboot phase lost 2 of 600. Every admitted identity in these phases
reached Sentinel. The verifier checks each failure recorded in
`summary.json`; verifying its evidence does not make the failed phase pass.
The separate temporal-proof JSON binds the outage inputs by SHA-256
and records queue receipt and Sentinel ingestion bounds.

To verify the retained files offline, run this from
`docs/evidence/ws6-20261101-final`:

```sh
python3 - <<'PY'
import hashlib
import json
import re
from pathlib import Path

root = Path.cwd().resolve()
summary = json.loads((root / 'summary.json').read_text())
columns = ['EventId', 'Copies', 'FirstGenerated', 'LastGenerated',
           'FirstIngested', 'LastIngested']

def require(value, message):
    if not value:
        raise SystemExit(message)

def artifact(record):
    path = (root / record['file']).resolve()
    require(root in path.parents, 'artifact escaped evidence directory')
    data = path.read_bytes()
    require(len(data) == record['bytes'], 'byte count mismatch')
    require(hashlib.sha256(data).hexdigest() == record['sha256'], 'hash mismatch')
    return data

def source(record, pattern):
    values = artifact(record).decode('ascii').splitlines()
    require(len(values) == len(set(values)) == record['count'], 'source count/duplicates')
    require(all(re.fullmatch(pattern, value) for value in values), 'identity format')
    return set(values)

def windows_source(record):
    values = source(record, r'winevt-[a-f0-9]{32}')
    hashes = record['attestedSourceFileSha256']
    require(set(hashes) == {'native', 'forwarded', 'queue'}, 'missing attestation')
    require(set(hashes.values()) == {record['sha256']}, 'attestation mismatch')
    return values

def rows(record, expected_columns):
    require(record['columns'] == expected_columns, 'column mismatch')
    values = [json.loads(line) for line in artifact(record).decode('ascii').splitlines()]
    require(len(values) == record['rowCount'], 'row count mismatch')
    require(all(isinstance(row, list) and len(row) == len(expected_columns)
                for row in values), 'invalid row')
    return values

def destination(record, expected):
    values = rows(record, columns)
    require(all(type(row[1]) is int and row[1] == 1 for row in values), 'duplicate copies')
    found = [row[0] for row in values]
    require(len(found) == len(set(found)) == len(expected), 'destination count mismatch')
    require(set(found) == expected, 'destination identity mismatch')

def digest(values):
    return hashlib.sha256('\n'.join(sorted(values)).encode('ascii')).hexdigest()

verified = []
for name in ('steady', 'diagnostic1000', 'burst', 'outage', 'bufferedRestart'):
    phase = summary['windowsWec'][name]
    evidence = phase['identityEvidence']
    expected = windows_source(evidence['source'])
    warmup = windows_source(phase['warmup']['identityEvidence'])
    require(not expected & warmup, 'warmup overlaps measured phase')
    require(len(expected) == phase['expectedCount'], 'expected count mismatch')
    require(digest(expected) == phase['expectedSetSha256'], 'identity-set hash mismatch')
    destination(evidence['destination'], expected)
    verified.append({'source': 'windows', 'phase': name, 'count': len(expected)})

for name in ('previousFailedSteady', 'previousFailedBurst'):
    windows_source(summary['windowsWec'][name]['identityEvidence'])

firewall_phases = [(name, summary['firewall'][name]) for name in ('steady', 'burst', 'destinationOutage')]
firewall_phases.extend(summary['firewall'].get('sourceFaults', {}).items())
idle = summary['firewall'].get('idleGaps')
if idle and idle['strictPass']:
    firewall_phases.append(('idleGaps', idle))
for name, phase in firewall_phases:
    evidence = phase['identityEvidence']
    expected = source(evidence['expected'], r'a13-n[0-9]{4,5}x[0-9]{5}')
    generated = set()
    for block in evidence['expected']['expectedBlocks']:
        match = re.fullmatch(r'nft:A:(\d+):(\d+)', block)
        require(match is not None, 'invalid frozen firewall block')
        first, count = map(int, match.groups())
        require(0 < count <= 200000 and first + count <= 2000000, 'block bounds')
        identities = {'a13-n{}x{}'.format(4400 + n // 40000, 20000 + n % 40000)
                      for n in range(first, first + count)}
        require(not generated & identities, 'overlapping firewall blocks')
        generated.update(identities)
    require(generated == expected, 'frozen plan identity mismatch')
    require(len(expected) == phase['expected'] == phase['native']['nativeCounterDelta'],
            'native count mismatch')
    queue = rows(evidence['queue'], ['EventId', 'GeneratedAt', 'ReceivedAt'])
    queued = [row[0] for row in queue]
    require(len(queued) == len(set(queued)) == len(expected) and set(queued) == expected,
            'queue identity mismatch')
    for stage in ('native', 'queue', 'sentinel'):
        require(digest(expected) == phase[stage]['identitySetSha256'], 'set hash mismatch')
    destination(evidence['destination'], expected)
    verified.append({'source': 'firewall', 'phase': name, 'count': len(expected)})

artifact(summary['firewall']['destinationOutage']['temporalProof'])
artifact(summary['windowsWec']['outage']['temporalProof'])
restart = json.loads(artifact(summary['windowsWec']['bufferedRestart']['bufferedRestartProof']))
full_sets = [source(restart['fullQueueIdentityEvidence'][name], r'winevt-[a-f0-9]{32}')
             for name in ('before', 'pre-kill', 'after')]
require(full_sets[0] == full_sets[1] == full_sets[2] and len(full_sets[0]) == 50366,
        'restart full queue set not preserved')
phase_ids = windows_source(summary['windowsWec']['bufferedRestart']['identityEvidence']['source'])
require(phase_ids <= full_sets[0], 'measured restart phase absent from queue snapshot')
snapshots = restart['snapshots']
require(len({value['bookmarkRecordId'] for value in snapshots.values()}) == 1,
        'restart bookmark changed')
require(snapshots['before']['processId'] == restart['crash']['killedPid'] != snapshots['after']['processId'],
        'restart process identity mismatch')
require(restart['acceptedQueueRecoveryVerified'] and restart['phaseDestinationQueryVerified'],
        'restart proof not verified')
for phase in summary['firewall'].get('sourceFaults', {}).values():
    artifact(phase['actualFaultProof'])
failed_firewall = []
for name, phase in summary['firewall'].get('failedSourceFaults', {}).items():
    evidence = phase['identityEvidence']
    expected = source(evidence['expected'], r'a13-n[0-9]{4,5}x[0-9]{5}')
    missing = source(evidence['missing'], r'a13-n[0-9]{4,5}x[0-9]{5}')
    queue = rows(evidence['queue'], ['EventId', 'GeneratedAt', 'ReceivedAt'])
    accepted = {row[0] for row in queue}
    require(len(accepted) == len(queue) == phase['queue']['distinctIds'], 'failed queue count')
    require(accepted <= expected and expected - accepted == missing, 'failed missing set')
    require(digest(expected) == phase['expectedSetSha256'], 'failed expected hash')
    require(digest(missing) == phase['queue']['missingSetSha256'] == phase['sentinel']['missingSetSha256'], 'failed missing hash')
    require(len(missing) == phase['queue']['missing'] == phase['sentinel']['missing'], 'failed missing count')
    destination(evidence['destination'], accepted)
    require(phase['strictPass'] is False and phase['deliveryQualified'] is False, 'failure relabelled')
    artifact(phase['actualFaultProof'])
    failed_firewall.append({'phase': name, 'expected': len(expected), 'accepted': len(accepted), 'missing': len(missing)})
if 'sourceFaultCaptureHelper' in summary['firewall']:
    artifact(summary['firewall']['sourceFaultCaptureHelper'])

if idle:
    from datetime import datetime
    proof = json.loads(artifact(idle['idleProof']))
    require(proof['planSha256'] == idle['planSha256'] ==
            'f634d707fb43c75df526217330663c471cc4d5054a4e4cc24c171af5084c5a58',
            'idle frozen plan mismatch')
    require(len(proof['pulses']) == 4 and len(proof['gaps']) == 3,
            'idle pulse/gap count')
    require(sum(p['nativeCounterDelta']['A'] for p in proof['pulses']) == 6300,
            'idle native count')
    for left, right, gap in zip(proof['pulses'], proof['pulses'][1:], proof['gaps']):
        observed = (datetime.fromisoformat(right['startedAt']) -
                    datetime.fromisoformat(left['endedAt'])).total_seconds()
        require(observed == gap['observedGapSeconds'] and observed > 0,
                'idle observed timing mismatch')
    require(proof['gaps'] == idle['observedGaps'], 'idle summary timing mismatch')
    require(len(proof['queueMeasurements']) == 4 and
            all(item['settleLimitSeconds'] == 1200 for item in proof['queueMeasurements']),
            'idle queue settle limits changed')
    require([gap['plannedGapMinutes'] for gap in proof['gaps']] == [5, 30, 65],
            'idle planned gaps changed')
    require(proof['pulses'] == idle['nativeGeneratorReports'], 'idle native report mismatch')
    for item, count in zip(proof['queueMeasurements'], (100, 100, 100, 6000)):
        listener = item['listeners']['a13']
        require(listener['expected'] == count and
                listener['accepted'] + listener['missing'] == count,
                'idle per-pulse queue accounting mismatch')
        require(item['passed'] is (listener['missing'] == 0 and listener['malformedKeys'] == 0),
                'idle queue measurement outcome changed')
        require(item['receipt']['status'] == 'Success', 'idle queue receipt failed')
    queue_gates = all(item['passed'] is True for item in proof['queueMeasurements'])
    require(idle['queueSettleGatesPassed'] is queue_gates, 'idle queue gates changed')
    require(idle['collectionGatesPassed'] is (proof['collection']['complete'] is True and queue_gates),
            'idle collection gate changed')
    require(idle['qualificationPassed'] is (idle['strictPass'] and idle['collectionGatesPassed']),
            'idle qualification outcome changed')
    if not idle['strictPass']:
        evidence = idle['identityEvidence']
        expected = source(evidence['expected'], r'a13-n[0-9]{4,5}x[0-9]{5}')
        queued = rows(evidence['queue'], ['EventId', 'GeneratedAt', 'ReceivedAt'])
        observed = rows(evidence['destination'], columns)
        for stage, values in [('queue', queued), ('sentinel', observed)]:
            found = {row[0] for row in values}
            require(len(found) == len(values) == idle[stage]['distinctIds'], 'idle row count')
            require(digest(found) == idle[stage]['identitySetSha256'], 'idle set hash')
            require(len(expected - found) == idle[stage]['missing'] and
                    len(found - expected) == idle[stage]['extra'], 'idle missing/extra count')
        duplicate_rows = sum(row[1] - 1 for row in observed)
        require(duplicate_rows == idle['sentinel']['duplicateRows'], 'idle duplicates')
        require(any(idle[stage][field] for stage in ('queue', 'sentinel')
                    for field in ('missing', 'extra')) or duplicate_rows > 0,
                'idle failure not supported by retained sets')

print(json.dumps({'verifiedPhases': verified, 'verifiedFailedSourceFiles': 2,
                  'verifiedFailedFirewallPhases': failed_firewall,
                  'overallQualificationClaim': False}, indent=2))
PY
```
