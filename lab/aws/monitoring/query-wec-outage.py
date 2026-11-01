#!/usr/bin/env python3
"""Metadata-only Sentinel observation during an owned Windows outage; never delivery proof."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('wec_outage_transport', ROOT / 'query-firewall.py')
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
COLUMNS = [{'name': 'Rows', 'type': 'long'}, {'name': 'FirstIngestedAt', 'type': 'datetime'},
           {'name': 'LastIngestedAt', 'type': 'datetime'}]


def scope(plan, since, until, cutoff):
    run, phase = plan['runId'], plan['phase']
    measured = plan['measured']
    if (not isinstance(run, str) or not re.fullmatch(r'bower-ws6-[0-9]{8}-[0-9]{6}', run)
            or not isinstance(phase, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', phase)
            or plan['kind'] != 'native-windows-wec-destination-outage'
            or plan['status'] != 'frozen-before-dispatch'
            or any(type(measured[key]) is not int or measured[key] != value
                   for key, value in [('rate', 10), ('seconds', 3600), ('expectedNativeCount', 36000)])
            or not 0 < until - since <= 7200 or until > cutoff):
        raise ValueError('outage-observation-scope')
    return run + '-windows'


def query_text(plan, since, until, cutoff):
    collector = scope(plan, since, until, cutoff)
    return ('BowerSecurity_CL\n'
            f'| where CollectorId == "{collector}"\n'
            '| where ApplicationName == "windows-security" and ApplicationEnvironment == "production"\n'
            '| where EventType == "authentication_failure"\n'
            f'| where TimeGenerated >= datetime({transport.iso(since)}) and TimeGenerated < datetime({transport.iso(until)})\n'
            f'| where ingestion_time() <= datetime({transport.iso(cutoff)})\n'
            '| summarize Rows=count(), FirstIngestedAt=min(ingestion_time()), LastIngestedAt=max(ingestion_time())')


def summarize(data, cutoff):
    transport.reject_partial(data)
    tables = data['tables']
    if (not isinstance(tables, list) or len(tables) != 1 or tables[0].get('name') != 'PrimaryResult'
            or tables[0].get('columns') != COLUMNS or len(tables[0].get('rows', [])) != 1):
        raise ValueError('outage-observation-schema')
    row = tables[0]['rows'][0]
    if not isinstance(row, list) or len(row) != 3 or type(row[0]) is not int or not 0 <= row[0] < 2 ** 63:
        raise ValueError('outage-observation-row')
    count, first, last = row
    if count == 0:
        if first is not None or last is not None:
            raise ValueError('outage-observation-empty-timestamps')
    else:
        first_stamp, last_stamp = transport.stamp(first), transport.stamp(last)
        if not first_stamp <= last_stamp <= cutoff:
            raise ValueError('outage-observation-timestamps')
        first, last = transport.iso(first_stamp), transport.iso(last_stamp)
    return {'rows': count, 'firstIngestedAt': first, 'lastIngestedAt': last,
            'noIngestionObservedAtCutoff': count == 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--since', required=True, help='Verified warm-up completion UTC timestamp')
    parser.add_argument('--until', help='Exclusive event-time bound; defaults to this query cutoff')
    parser.add_argument('--azure-state-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise ValueError('new-output-file-required')
    with args.plan.open('rb') as stream:
        plan_bytes = stream.read(65537)
    if not plan_bytes or len(plan_bytes) > 65536:
        raise ValueError('outage-plan-bound')
    plan = json.loads(plan_bytes)
    plan_hash = hashlib.sha256(plan_bytes).hexdigest()
    verifier_hash = transport.sha(Path(__file__))
    transport_hash = transport.sha(ROOT / 'query-firewall.py')
    cutoff = dt.datetime.now(dt.timezone.utc).timestamp()
    since = transport.stamp(args.since)
    until = transport.stamp(args.until) if args.until else cutoff
    query = query_text(plan, since, until, cutoff)
    data, workspace, verifier = transport.query_live(args.azure_state_dir, query)
    summary = summarize(data, cutoff)
    if transport.sha(args.plan) != plan_hash:
        raise ValueError('outage-plan-changed')
    report = {'schemaVersion': 1, 'kind': 'windows-outage-destination-observation',
              'runId': plan['runId'], 'phase': plan['phase'], 'planSha256': plan_hash,
              'eventWindowStartedAt': transport.iso(since), 'eventWindowEndedAt': transport.iso(until),
              'queryCutoff': transport.iso(cutoff), 'queryCompletedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
              'workspaceId': workspace, 'verifierApplicationId': verifier, 'query': query,
              'querySha256': hashlib.sha256(query.encode()).hexdigest(), 'queryResponseComplete': True,
              'observation': summary, 'destinationQueryVerified': False, 'deliveryQualified': False,
              'qualificationScope': 'One metadata-only observation. Indexing may lag; final exact identity and ingestion-time reconciliation is mandatory.',
              'verifierSha256': verifier_hash, 'transportSha256': transport_hash}
    encoded = (json.dumps(report, indent=2) + '\n').encode()
    if len(encoded) > 65536:
        raise ValueError('outage-observation-report-bound')
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({key: report[key] for key in ['kind', 'phase', 'queryCutoff', 'queryResponseComplete',
                                                   'observation', 'destinationQueryVerified', 'deliveryQualified']}))
    return 0 if summary['noIngestionObservedAtCutoff'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'observation': 'failed', 'category': type(error).__name__, 'deliveryQualified': False}))
        raise SystemExit(2) from None
