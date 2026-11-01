#!/usr/bin/env python3
"""Independently reconcile Windows native/WEC/queue identities with Sentinel metadata."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys

# Reuse the reviewed isolated verifier identity/cache and bounded HTTPS transport.
# Importing this sibling defines functions only; it never signs in or queries.
SHARED_PATH = Path(__file__).with_name('query-firewall.py')
_spec = importlib.util.spec_from_file_location('bower_wec_verifier_transport', SHARED_PATH)
transport = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(transport)

MAX_ROWS = transport.MAX_ROWS
MAX_NATIVE = 50000
MAX_ID_BYTES = MAX_ROWS * 42
IDENTITY = re.compile(r'winevt-[a-f0-9]{32}')
COLUMNS = ['EventId', 'Copies', 'FirstGenerated', 'LastGenerated', 'FirstIngested', 'LastIngested']
TYPES = ['string', 'long', 'datetime', 'datetime', 'datetime', 'datetime']


def require(condition, code):
    if not condition:
        raise ValueError(code)


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def digest(identities):
    """Canonical set digest: UTF-8, sorted IDs, LF separators, no trailing LF."""
    return hashlib.sha256('\n'.join(sorted(identities)).encode('ascii')).hexdigest()


def read_ids(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_ID_BYTES + 1)
    require(0 < len(raw) <= MAX_ID_BYTES, 'identity-file-size')
    text = raw.decode('ascii').replace('\r\n', '\n')
    require('\r' not in text, 'identity-file-line-endings')
    rows = text.split('\n')
    if rows[-1] == '':
        rows.pop()
    require(0 < len(rows) <= MAX_ROWS and all(IDENTITY.fullmatch(row) for row in rows), 'identity-file-format')
    require(len(set(rows)) == len(rows), 'duplicate-source-identity')
    return {'ids': set(rows), 'fileSha256': hashlib.sha256(raw).hexdigest()}


def source_evidence(phase, native, forwarded, queue):
    run = phase.get('runId', '')
    require(isinstance(run, str) and re.fullmatch(r'bower-ws6-\d{8}-\d{6}', run), 'run-scope')
    name = phase.get('phase', '')
    require(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name), 'phase-scope')
    rate = phase['requestedRate']
    require(type(rate) is int and rate in (10, 100), 'requested-rate')
    begin, end = transport.stamp(phase['startedAt']), transport.stamp(phase['endedAt'])
    require(0 < end - begin <= 3635, 'phase-time-window')
    event_end = transport.stamp(phase['eventWindowEndedAt'])
    require(type(phase['eventWindowPaddingSeconds']) is int and phase['eventWindowPaddingSeconds'] == 5
            and abs(event_end - end - 5) <= .000001, 'native-event-window-padding')
    require(phase.get('mode', 'phase') == 'phase', 'diagnostic-not-qualification')
    generator = phase['generator']
    isolation = generator['credentialIsolation']
    require(isolation in ('per-worker-logon-new-credentials', 'per-phase-logon-new-credentials', 'per-process-logon-new-credentials')
            and generator['initialized'] is True and generator['sessionResultCodes'] == {}
            and generator['initializationFailureReasons'] == {}
            and transport.stamp(generator['startedAt']) == begin
            and transport.stamp(generator['endedAt']) == end, 'generator-session-or-time')
    for failure in ('sessionSetupFailures', 'impersonationFailures', 'revertFailures', 'handleCloseFailures', 'sessionCleanupFailures'):
        require(type(generator[failure]) is int and generator[failure] == 0, 'generator-session-failure')
    cleanup_codes = generator['sessionCleanupCodes']
    require(isinstance(cleanup_codes, dict) and all(code in ('0', '2250') and type(amount) is int and amount > 0
            for code, amount in cleanup_codes.items()) and sum(cleanup_codes.values()) <= 64, 'generator-session-cleanup')
    count = generator['requested']
    require(type(count) is int and 0 < count <= MAX_NATIVE and count % rate == 0
            and count / rate <= 3600, 'requested-count')
    if isolation in ('per-phase-logon-new-credentials', 'per-process-logon-new-credentials') or 'credentialMode' in generator:
        require(generator['executionKind'] == 'native-windows'
                and generator['credentialMode'] == 'explicit-stable-per-phase'
                and type(generator['workerCount']) is int and generator['workerCount'] == min(64 if isolation == 'per-phase-logon-new-credentials' else 4, count)
                and type(generator['activeAtReturn']) is int and generator['activeAtReturn'] == 0
                and type(generator['workersRemainingAtReturn']) is int and generator['workersRemainingAtReturn'] == 0
                and sum(cleanup_codes.values()) == (1 if isolation == 'per-phase-logon-new-credentials' else generator['workerCount']), 'phase-session-accounting')
        warmup = generator['warmup']
        require(generator['warmupRequired'] is True and generator['warmupVerified'] is True
                and isinstance(warmup, dict) and warmup['kind'] == 'native-warmup'
                and all(type(warmup[key]) is int and warmup[key] == 100 for key in ('requested', 'scheduled', 'completed'))
                and type(warmup['requestedRate']) is int and warmup['requestedRate'] == 10
                and warmup['drained'] is True and warmup['unexpectedSuccesses'] == 0
                and warmup['resultCodes'] == {'1326': 100}, 'warmup-attempt-accounting')
        warm_begin, warm_end = transport.stamp(warmup['startedAt']), transport.stamp(warmup['endedAt'])
        warm_done, warm_deadline = transport.stamp(warmup['completedAt']), transport.stamp(warmup['deadlineAt'])
        require(0 < warm_end - warm_begin <= 30 and abs(warm_deadline - warm_begin - 30) <= .000001
                and warm_end + 5 <= warm_done <= begin and warm_done <= warm_deadline, 'warmup-window')
        warm_count = warmup['nativeCount']
        require(type(warm_count) is int and 0 < warm_count <= 100
                and type(warmup['forwardedCount']) is int and warmup['forwardedCount'] == warm_count
                and type(warmup['queueCount']) is int and warmup['queueCount'] == warm_count
                and isinstance(warmup['nativeIdsSha256'], str) and re.fullmatch(r'[0-9a-f]{64}', warmup['nativeIdsSha256'])
                and warmup['nativeIdsSha256'] == warmup['forwardedIdsSha256'] == warmup['queueIdsSha256'], 'warmup-source-evidence')
    require(all(type(generator[key]) is int and generator[key] == count for key in ('scheduled', 'completed')),
            'incomplete-generator')
    require(type(generator['unexpectedSuccesses']) is int and generator['unexpectedSuccesses'] == 0
            and generator['drained'] is True and generator['cancelled'] is False, 'generator-failed')
    codes = generator['resultCodes']
    require(type(generator['maxConcurrency']) is int and 1 <= generator['maxConcurrency'] <= 64
            and isinstance(codes, dict) and codes and '1219' not in codes
            and all(isinstance(code, str) and re.fullmatch(r'[1-9][0-9]{0,9}', code)
                    and type(amount) is int and amount > 0 for code, amount in codes.items())
            and sum(codes.values()) == count, 'generator-result-accounting')
    seconds, actual_rate = generator['seconds'], generator['actualRate']
    require(finite(seconds) and finite(actual_rate) and count / rate - .1 <= seconds <= 3635
            and .99 * rate <= actual_rate <= 1.01 * rate
            and abs(count / seconds - actual_rate) <= max(.01, rate * .001)
            and abs((end - begin) - seconds) <= max(1, seconds * .01), 'generator-rate-or-clock')
    require(phase['nativeVerified'] is True, 'native-not-verified')
    expected = native['ids']
    require(len(expected) == count and native['ids'] == forwarded['ids'] == queue['ids'], 'source-identity-mismatch')
    for label, evidence in [('native', native), ('forwarded', forwarded)]:
        summary = phase[label]
        require(all(type(summary[key]) is int and summary[key] == count for key in ('count', 'unique'))
                and type(summary['invalidNetworkLogons']) is int and summary['invalidNetworkLogons'] == 0
                and summary['idsSha256'] == evidence['fileSha256'], 'source-summary-or-file-hash')
    first_native = transport.stamp(phase['native']['firstEventAt'])
    last_native = transport.stamp(phase['native']['lastEventAt'])
    observed_rate = phase['native']['observedRate']
    require(begin <= first_native < last_native < event_end and finite(observed_rate)
            and observed_rate >= .99 * rate
            and abs((count - 1) / (last_native - first_native) - observed_rate) <= max(.01, rate * .001),
            'native-observed-rate-or-window')
    accepted = phase['queueIdentities']
    require(type(accepted['count']) is int and accepted['count'] == count
            and accepted['exactNativeMatch'] is True and accepted['idsSha256'] == queue['fileSha256'], 'queue-summary-or-file-hash')
    require(type(phase['acceptedDelta']) is int and phase['acceptedDelta'] == count, 'accepted-count')
    before, after = phase['sourceBefore'], phase['sourceAfter']
    for sample in (before, after):
        require(sample['id'] == 'wec-security' and sample['channel'] == 'ForwardedEvents'
                and sample['state'] == 'running', 'source-status')
    require(type(before['queued']) is int and type(after['queued']) is int
            and before['queued'] >= 0 and after['queued'] - before['queued'] == count, 'source-accepted-delta')
    for counter in ('rejected', 'parserErrors', 'malformed', 'oversized', 'gaps', 'resets', 'cursorConflicts'):
        require(type(before[counter]) is int and type(after[counter]) is int
                and before[counter] >= 0 and after[counter] == before[counter], 'source-error-counter')
    return {'runId': run, 'collectorId': run + '-windows', 'phase': name, 'start': begin, 'end': event_end,
            'attemptsEnd': end, 'firstNativeAt': first_native, 'lastNativeAt': last_native, 'nativeObservedRate': observed_rate,
            'expected': expected, 'requestedRate': rate, 'actualRate': actual_rate, 'count': count,
            'fileSha256': {label: evidence['fileSha256'] for label, evidence in
                           [('native', native), ('forwarded', forwarded), ('queue', queue)]}}


def query_text(source, cutoff):
    require(finite(cutoff) and cutoff >= source['end'], 'query-before-phase-ended')
    # Query the whole scoped authentication population, not just an EventId-in list:
    # filtering by the expected IDs would hide unexpected destination identities.
    return '''BowerSecurity_CL
| where CollectorId == "{collector}" and ApplicationName == "windows-security"
    and ApplicationEnvironment == "production" and EventType == "authentication_failure"
| where TimeGenerated >= datetime({start}) and TimeGenerated < datetime({end})
| where ingestion_time() <= datetime({cutoff})
| summarize Copies=count(), FirstGenerated=min(TimeGenerated), LastGenerated=max(TimeGenerated),
    FirstIngested=min(ingestion_time()), LastIngested=max(ingestion_time()) by EventId
| project EventId, Copies, FirstGenerated, LastGenerated, FirstIngested, LastIngested
| take {limit}'''.format(collector=source['collectorId'], start=transport.iso(source['start']),
                       end=transport.iso(source['end']), cutoff=transport.iso(cutoff), limit=MAX_ROWS + 1)


def destination_rows(data, source, cutoff):
    transport.reject_partial(data)
    tables = data.get('tables', [])
    require(isinstance(tables, list) and len(tables) == 1, 'query-tables')
    table = tables[0]
    require([column['name'] for column in table['columns']] == COLUMNS
            and [column['type'] for column in table['columns']] == TYPES, 'query-schema')
    rows = table['rows']
    require(isinstance(rows, list) and len(rows) <= MAX_ROWS, 'query-row-bound')
    identities = {}
    for row in rows:
        require(isinstance(row, list) and len(row) == 6 and isinstance(row[0], str)
                and IDENTITY.fullmatch(row[0]) and row[0] not in identities
                and type(row[1]) is int and 1 <= row[1] <= 2 ** 63 - 1, 'query-identity')
        generated = [transport.stamp(row[2]), transport.stamp(row[3])]
        ingested = [transport.stamp(row[4]), transport.stamp(row[5])]
        require(source['start'] <= generated[0] <= generated[1] < source['end']
                and source['start'] <= ingested[0] <= ingested[1] <= cutoff, 'query-time-scope')
        identities[row[0]] = row[1]
    return identities


def reconcile(source, data, cutoff):
    require(finite(cutoff) and cutoff >= source['end'], 'query-cutoff')
    actual = destination_rows(data, source, cutoff)
    expected = source['expected']
    found = set(actual)
    missing, extra = expected - found, found - expected
    duplicate_ids = {identity for identity, copies in actual.items() if copies > 1}
    duplicate_rows = sum(copies - 1 for copies in actual.values())
    rows = sorted(data['tables'][0]['rows'], key=lambda row: row[0])
    extrema = {}
    for label, index, operation in [('firstGeneratedAt', 2, min), ('lastGeneratedAt', 3, max),
                                     ('firstIngestedAt', 4, min), ('lastIngestedAt', 5, max)]:
        extrema[label] = transport.iso(operation(transport.stamp(row[index]) for row in rows)) if rows else None
    strict = not missing and not extra and not duplicate_rows
    return {
        'schemaVersion': 1, 'runId': source['runId'], 'collectorId': source['collectorId'], 'phase': source['phase'],
        'startedAt': transport.iso(source['start']), 'endedAt': transport.iso(source['attemptsEnd']),
        'eventWindowEndedAt': transport.iso(source['end']), 'eventWindowPaddingSeconds': 5,
        'nativeFirstEventAt': transport.iso(source['firstNativeAt']), 'nativeLastEventAt': transport.iso(source['lastNativeAt']),
        'nativeObservedRate': source['nativeObservedRate'],
        'queryCutoffAt': transport.iso(cutoff), 'requestedRate': source['requestedRate'], 'actualRate': source['actualRate'],
        'nativeVerified': True, 'expectedCount': len(expected), 'expectedSetSha256': digest(expected),
        'sourceIdentityFileSha256': source['fileSha256'], 'forwardedExactMatch': True, 'queueExactMatch': True,
        'sentinel': {'distinct': len(found), 'rows': sum(actual.values()), 'missing': len(missing), 'extra': len(extra),
                     'duplicateRows': duplicate_rows, 'duplicateIdentities': len(duplicate_ids),
                     'identitySetSha256': digest(found), 'missingSetSha256': digest(missing),
                     'extraSetSha256': digest(extra), 'duplicateSetSha256': digest(duplicate_ids), **extrema},
        'identityComplete': not missing and not extra, 'strictPass': strict, 'destinationQueryVerified': strict,
        'queryResponseComplete': True, 'destinationColumns': COLUMNS, 'destinationIdentityRows': rows,
        'qualificationScope': 'This phase identity reconciliation only; outage, recovery and cleanup require separate evidence.',
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', type=Path, required=True, help='Exported phase JSON')
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--forwarded', type=Path, required=True)
    parser.add_argument('--queue', type=Path, required=True, help='Exported exact accepted queue ID file')
    parser.add_argument('--azure-state-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    require(not args.output.exists(), 'output-already-exists')
    with args.phase.open('rb') as stream:
        phase_bytes = stream.read(1024 * 1024 + 1)
    require(len(phase_bytes) <= 1024 * 1024, 'phase-file-size')
    phase = json.loads(phase_bytes)  # bytes decoding also accepts Windows UTF-8 BOM.
    source = source_evidence(phase, read_ids(args.native), read_ids(args.forwarded), read_ids(args.queue))
    source_hashes = {Path(__file__).name: transport.sha(__file__), SHARED_PATH.name: transport.sha(SHARED_PATH)}
    cutoff = dt.datetime.now(dt.timezone.utc).timestamp()
    query = query_text(source, cutoff)
    data, workspace, verifier = transport.query_live(args.azure_state_dir, query)
    report = reconcile(source, data, cutoff)
    report.update(workspaceId=workspace, verifierClientId=verifier,
                  phaseEvidenceSha256=hashlib.sha256(phase_bytes).hexdigest(), queryText=query,
                  querySha256=hashlib.sha256(query.encode()).hexdigest(),
                  verifierSourceSha256=source_hashes,
                  queryCompletedAt=dt.datetime.now(dt.timezone.utc).isoformat())
    os.umask(0o077)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: value for key, value in report.items() if key not in ('destinationIdentityRows', 'queryText')}))
    return 0 if report['strictPass'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        # Never echo CLI output, HTTP bodies, bearer tokens, certificate contents or payloads.
        print(json.dumps({'status': 'failed', 'errorType': type(error).__name__}), file=sys.stderr)
        sys.exit(2)
