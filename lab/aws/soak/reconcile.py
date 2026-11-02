#!/usr/bin/env python3
"""Reconcile the soak: native, accepted and independently queried Sentinel identities per
collector, ingestion latency per hour, collector_health records, privacy markers, Azure Monitor
alerts and resource trends. Operator side; reads only what the on-host agents uploaded to the
run bucket and queries Sentinel with the separate read-only verifier identity.

  reconcile.py fetch  --lab-dir DIR                     # S3 results -> DIR/results (private)
  reconcile.py smoke|interim|final --lab-dir DIR --out FILE.json [--cutoff EPOCH]

Exact sets are compared by SHA-256 of the sorted identities joined by newline. Duplicate
Sentinel rows are counted separately. Writes metadata and digests only, never identity lists.
"""
import argparse
import datetime as dt
import gzip
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('query_firewall', HERE.parent / 'monitoring' / 'query-firewall.py')
qf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qf)

RUN = 'bower-soak-20261102-015614'
SMOKE_START, SOAK_START, SOAK_SECONDS = 1793587800, 1793590500, 86400
SMOKE_SECONDS = 900
COLLECTORS = {'linux': (RUN + '-linux', 'network_connection_denied'),
              'windows': (RUN + '-windows', 'authentication_failure')}
# Pre-registered latency gate: the pilot's connected-steady p99 (firewall 6.65 s, WEC 9.08 s,
# docs/evidence/pilot-native-20261030) times two, for the whole soak and for every hour.
LATENCY_P99_LIMIT = {'linux': 13.3, 'windows': 18.16}
PRIVACY_MARKERS = ('bower-probe', 'BOWER_DENY', 'synthetic-invalid')


def aws(*args):
    return subprocess.run(['aws', '--profile', 'homelab-admin', '--region', 'ap-southeast-2', *args],
                          check=True, capture_output=True, text=True, timeout=600).stdout


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def digest(ids):
    return hashlib.sha256('\n'.join(sorted(ids)).encode()).hexdigest()


def fetch(lab):
    if json.loads(aws('sts', 'get-caller-identity'))['Account'] != '959038055523':
        raise SystemExit('Unexpected AWS account')
    bucket = json.loads((lab / 'state.json').read_text())['outputs']['Artifacts']
    tags = {t['Key']: t['Value'] for t in json.loads(aws('s3api', 'get-bucket-tagging', '--bucket', bucket))['TagSet']}
    if tags.get('Project') != 'bower-lab' or tags.get('RunId') != RUN:
        raise SystemExit('Bucket is outside this run')
    out = lab / 'results'
    aws('s3', 'sync', 's3://%s/results/soak/%s/' % (bucket, RUN), str(out / 'hosts'), '--only-show-errors')
    aws('s3', 'sync', 's3://%s/results/sender/soak/%s/' % (bucket, RUN), str(out / 'sender'), '--only-show-errors')
    print(json.dumps({'fetched': sorted(str(p.relative_to(out)) for p in out.rglob('*') if p.is_file())[:60]}))


def firewall_ids(first, count):
    return {'a13-n{}x{}'.format(4400 + n // 40000, 20000 + n % 40000) for n in range(first, first + count)}


def firewall_native(results, label, cutoff):
    """Expected identities. Finished segments: exact, with the nftables counter delta. A segment
    still running at the cutoff contributes only its scheduled prefix (interim only)."""
    path = results / 'sender' / label / 'segments.jsonl'
    segments = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    plan_first = 0 if label == 'smoke' else 100000
    ids, records, counter_ok = set(), [], True
    next_first = plan_first
    for s in segments:
        g = s.get('generator') or {}
        delta = (g.get('nativeCounterDelta') or {}).get('A')
        ok = s['exitCode'] == 0 and g.get('sent') == s['count'] and delta == s['count']
        counter_ok &= ok
        ids |= firewall_ids(s['first'], s['count'])
        records.append({'segment': s['segment'], 'first': s['first'], 'count': s['count'], 'rate': s['rate'],
                        'sent': g.get('sent'), 'nftCounterDelta': delta, 'actualRate': g.get('actualRate'),
                        'plannedStart': s['plannedStart'], 'startedAt': g.get('startedAt'), 'endedAt': g.get('endedAt'),
                        'lateSeconds': round(s['requestedStart'] - s['plannedStart'], 3), 'exact': ok})
        next_first = s['first'] + s['count']
    partial = 0
    start = SMOKE_START if label == 'smoke' else SOAK_START
    total = SMOKE_SECONDS if label == 'smoke' else SOAK_SECONDS
    if cutoff < start + total and label == 'soak':
        # Scheduled prefix of the running segment, 30 s behind the cutoff.
        offset = (segments[-1]['plannedStart'] - start + segments[-1]['count'] / segments[-1]['rate']) if segments else 0
        seconds = max(0, int(cutoff - 30 - (start + offset)))
        partial = seconds * 10  # the first soak segments are steady 10/sec until +2 h
        ids |= firewall_ids(next_first, partial)
    return ids, {'segments': records, 'finishedSegments': len(records), 'scheduledPrefixFromRunningSegment': partial,
                 'allFinishedSegmentsExact': counter_ok, 'expected': len(ids)}


def windows_native(results, windows):
    ids, meta = set(), []
    duplicates = 0
    for name in windows:
        # Scheduled hourly export, else the on-demand export of the same window (dc-native-window.ps1).
        path = next((p for p in (results / 'hosts' / 'dc' / sub / (name + '.json') for sub in ('native', 'manual')) if p.exists()), None)
        if path is None:
            meta.append({'window': name, 'missing': True})
            continue
        report = json.loads(path.read_text(encoding='utf-8-sig'))
        ids_path = path.with_name(name + '.ids') if path.parent.name == 'native' else path.with_name(name + '.json.ids')
        lines = ids_path.read_text(encoding='utf-8-sig').splitlines()
        window_ids = {line.split('\t')[0] for line in lines if line}
        duplicates += len(window_ids & ids) + report['duplicateIdentities']
        ids |= window_ids
        meta.append({'window': name, 'since': report['since'], 'until': report['until'], 'selected': report['selected'],
                     'distinct': report['distinct'], 'redactionChangedIds': report['redactionChangedIds'],
                     'identitySetSha256': report['identitySetSha256']})
    return ids, {'windows': meta, 'expected': len(ids), 'crossWindowOrInWindowDuplicates': duplicates}


def accepted(results, host):
    if host == 'linux':
        path = results / 'hosts' / 'linux' / 'accepted.tsv.gz'
        lines = gzip.open(path, 'rt').read().splitlines() if path.exists() else []
    else:
        path = results / 'hosts' / 'wec' / 'accepted.tsv'
        lines = path.read_text(encoding='utf-8-sig').splitlines() if path.exists() else []
    return {line.split('\t')[0] for line in lines if line}


class Verifier:
    def __init__(self, azure_dir):
        self.state, self.verifier, self.certificate, self.cache = qf.verifier_context(azure_dir)
        self.env = {**os.environ, 'AZURE_CONFIG_DIR': str(self.cache), 'AZURE_CORE_COLLECT_TELEMETRY': 'no'}
        self.az('login', '--service-principal', '--username', self.verifier['appId'], '--certificate',
                str(self.certificate), '--tenant', qf.TENANT)
        self.az('account', 'set', '--subscription', qf.SUBSCRIPTION)
        account = self.az('account', 'show')
        if account['user']['name'].lower() != self.verifier['appId'] or account['user']['type'].lower() != 'serviceprincipal':
            raise SystemExit('Unexpected verifier identity')

    def az(self, *args):
        result = subprocess.run(['az', *args, '--output', 'json', '--only-show-errors'], env=self.env,
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError('Verifier CLI operation failed; output suppressed')
        return json.loads(result.stdout) if result.stdout.strip() else None

    def query(self, text):
        token = self.az('account', 'get-access-token', '--resource', 'https://api.loganalytics.io/')['accessToken']
        request = urllib.request.Request('https://api.loganalytics.io/v1/workspaces/' + self.state['workspaceId'] + '/query',
                                         data=json.dumps({'query': text}).encode(), method='POST',
                                         headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        del token
        with urllib.request.build_opener(qf.NoRedirect).open(request, timeout=660) as response:
            body = response.read(qf.MAX_BYTES + 1)
        if len(body) > qf.MAX_BYTES:
            raise ValueError('Oversized query response')
        data = json.loads(body)
        qf.reject_partial(data)
        table = data['tables'][0]
        names = [c['name'] for c in table['columns']]
        return [dict(zip(names, row)) for row in table['rows']], hashlib.sha256(text.encode()).hexdigest()


def quantiles(values):
    values = sorted(values)
    pick = lambda f: round(values[max(0, math.ceil(len(values) * f) - 1)], 3) if values else None
    return {'count': len(values), 'p50': pick(.5), 'p95': pick(.95), 'p99': pick(.99), 'max': round(values[-1], 3) if values else None}


def stamp(value):
    return qf.stamp(value)


def sentinel(verifier, collector, event_type, start, end, cutoff, chunk=3600):
    """Every row of the collector's event type with TimeGenerated in [start, end), per chunk."""
    rows, hours, hashes = {}, [], []
    t = start
    while t < end:
        u = min(end, t + chunk)
        text = ('BowerSecurity_CL\n| where TimeGenerated >= datetime({a}) and TimeGenerated < datetime({b})\n'
                '| where CollectorId == "{c}" and EventType == "{e}"\n| where ingestion_time() <= datetime({k})\n'
                '| summarize Copies=count(), Generated=min(TimeGenerated), FirstIngested=min(ingestion_time()) by EventId\n'
                '| take 400001').format(a=iso(t), b=iso(u), c=collector, e=event_type, k=iso(cutoff))
        result, query_hash = verifier.query(text)
        if len(result) > 400000:
            raise ValueError('Chunk too large; reduce the chunk')
        hashes.append(query_hash)
        latencies = []
        for row in result:
            if row['EventId'] in rows:
                rows[row['EventId']]['Copies'] += row['Copies']  # an id spanning two chunks
                continue
            rows[row['EventId']] = row
            latencies.append(stamp(row['FirstIngested']) - stamp(row['Generated']))
        hours.append({'from': iso(t), 'to': iso(u), 'distinct': len(result), 'rows': sum(r['Copies'] for r in result),
                      'latencySeconds': quantiles(latencies)})
        t = u
    all_latencies = [stamp(r['FirstIngested']) - stamp(r['Generated']) for r in rows.values()]
    return rows, hours, quantiles(all_latencies), hashes


def health(verifier, start, end):
    text = ('BowerSecurity_CL\n| where TimeGenerated >= datetime({a}) and TimeGenerated < datetime({b})\n'
            '| where EventType == "collector_health"\n| summarize Records=count(), Earliest=min(TimeGenerated), Latest=max(TimeGenerated),'
            ' MaxGapSeconds=max(Gap) by CollectorId, Outcome=tostring(EventOutcomeReason)\n').format(a=iso(start), b=iso(end))
    text = text.replace('| summarize', '| order by CollectorId asc, TimeGenerated asc\n| extend Gap=iff(prev(CollectorId) == CollectorId,'
                        ' datetime_diff("second", TimeGenerated, prev(TimeGenerated)), 0)\n| summarize', 1)
    return verifier.query(text)


def privacy(verifier, start, end):
    condition = ' or '.join('Packed contains "%s"' % m for m in PRIVACY_MARKERS)
    text = ('BowerSecurity_CL\n| where TimeGenerated >= datetime({a}) and TimeGenerated < datetime({b})\n'
            '| where CollectorId startswith "{r}"\n| extend Packed=tostring(pack_all())\n'
            '| summarize Rows=count(), Matches=countif({m}) by CollectorId').format(a=iso(start), b=iso(end), r=RUN, m=condition)
    return verifier.query(text)


def alerts(state, start):
    """Azure Monitor alert instances and Sentinel incidents in the run's resource group (operator read)."""
    base = 'https://management.azure.com/subscriptions/' + qf.SUBSCRIPTION
    out = {}
    for name, url in (('alerts', base + '/providers/Microsoft.AlertsManagement/alerts?api-version=2019-05-05-preview'
                       '&targetResourceGroup=' + state['group'] + '&timeRange=30d'),
                      ('incidents', 'https://management.azure.com' + state['workspaceResourceId']
                       + '/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01')):
        result = subprocess.run(['az', 'rest', '--method', 'get', '--url', url, '--only-show-errors', '--output', 'json'],
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            out[name] = {'error': 'query-failed'}
            continue
        items = json.loads(result.stdout).get('value', [])
        out[name] = [{'name': (i.get('properties', {}).get('essentials', {}) or {}).get('alertRule', i.get('name', '')).split('/')[-1],
                      'state': (i.get('properties', {}).get('essentials', {}) or {}).get('monitorCondition') or i.get('properties', {}).get('status'),
                      'startedAt': (i.get('properties', {}).get('essentials', {}) or {}).get('startDateTime') or i.get('properties', {}).get('createdTimeUtc')}
                     for i in items]
    return out


def slope(points):
    """Least-squares slope per hour of (hours, value) points and the mean."""
    if len(points) < 3:
        return None
    n = len(points)
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    sxx = sum((x - mx) ** 2 for x, _ in points)
    sxy = sum((x - mx) * (y - my) for x, y in points)
    b = sxy / sxx if sxx else 0
    return {'samples': n, 'mean': round(my, 3), 'slopePerHour': round(b, 3),
            'thirtyDayProjectionPercentOfMean': round(100 * b * 720 / my, 2) if my else None,
            'min': min(y for _, y in points), 'max': max(y for _, y in points)}


def resources(results, host, start, end):
    path = results / 'hosts' / ('linux' if host == 'linux' else 'wec') / 'samples.jsonl'
    rows = [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()] if path.exists() else []
    rows = [r for r in rows if start <= stamp(r['at']) < end]
    good = [r for r in rows if not r.get('error') and r.get('process')]
    def series(get, warm=3):
        return slope([((stamp(r['at']) - start) / 3600, get(r)) for r in good if (stamp(r['at']) - start) / 3600 >= warm])
    pids = sorted({(r['process']['pid'], r['process'].get('startTicks') or r['process'].get('startedAt')) for r in good}, key=str)
    boots = sorted({r.get('bootId') or r.get('bootAt') for r in rows})
    if host == 'linux':
        mem, handles = (lambda r: r['process']['rssBytes']), (lambda r: r['process']['fds'])
        restarts = sorted({r['process']['nRestarts'] for r in good})
    else:
        mem, handles = (lambda r: r['process']['privateBytes']), (lambda r: r['process']['handles'])
        restarts = None
    store = lambda r: r['files'].get('queue.db', 0) + r['files'].get('queue.db-wal', 0)
    cpu = []
    for a, b in zip(good, good[1:]):
        gap = stamp(b['at']) - stamp(a['at'])
        if gap > 0 and a['process']['pid'] == b['process']['pid']:
            cpu.append(100 * (b['process']['cpuSeconds'] - a['process']['cpuSeconds']) / gap)
    jobs = {}
    for r in good:
        for job, value in (r.get('jobs') or {}).items():
            if value and value.get('lastRunAt'):
                jobs.setdefault(job, set()).add((value['lastRunAt'], value['lastState']))
    return {
        'samples': len(rows), 'failedSamples': len(rows) - len(good), 'processIdentities': len(pids), 'bootIds': len(boots),
        'serviceRestartCounter': restarts,
        'maximumSampleGapSeconds': max((stamp(b['at']) - stamp(a['at']) for a, b in zip(rows, rows[1:])), default=None),
        'memoryBytes': series(mem), 'memoryBytesFromStart': series(mem, 0),
        'handlesOrFds': series(handles), 'threads': series(lambda r: r['process']['threads']),
        'queueDbPlusWalBytes': series(store), 'walBytes': series(lambda r: r['files'].get('queue.db-wal', 0)),
        'cpuPercentOfOneCore': quantiles(cpu),
        'peakPending': max((r['queue']['pending'] for r in good), default=None),
        'peakOldestUndeliveredAgeSeconds': max((r['queue']['oldestAgeSeconds'] for r in good), default=None),
        'minimumDiskAvailableBytes': min((r['disk']['availableBytes'] for r in good), default=None),
        'statuses': sorted({r.get('status') for r in good}, key=str),
        'jobRuns': {job: {'runs': len(v), 'states': sorted({s for _, s in v}, key=str), 'last': max(v)[0]} for job, v in jobs.items()},
        'deliveryFailureCodes': sorted({(r.get('delivery') or {}).get('lastFailureCode') for r in good}, key=str),
    }


def compare(native, queue, rows):
    destination = set(rows)
    copies = sum(r['Copies'] for r in rows.values())
    return {'native': len(native), 'accepted': len(queue & native), 'sentinelDistinct': len(destination & native),
            'sentinelRows': copies, 'duplicateRows': copies - len(destination),
            'missingAtAccepted': len(native - queue), 'missingAtSentinel': len(native - destination),
            'extraAtSentinel': len(destination - native),
            'nativeSha256': digest(native), 'acceptedSha256': digest(queue & native), 'sentinelSha256': digest(destination & native),
            'exact': native == (queue & native) == (destination & native) and not (destination - native)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('fetch', 'smoke', 'interim', 'final'))
    parser.add_argument('--lab-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--cutoff', type=float, help='ingestion cutoff epoch (default now)')
    args = parser.parse_args()
    lab = args.lab_dir.resolve()
    if args.action == 'fetch':
        return fetch(lab)
    results = lab / 'results'
    cutoff = args.cutoff or dt.datetime.now(dt.timezone.utc).timestamp()
    verifier = Verifier(lab / 'azure')
    if args.action == 'smoke':
        start, end, label, windows = SMOKE_START, SMOKE_START + SMOKE_SECONDS + 60, 'smoke', ['smoke']
    elif args.action == 'interim':
        start, end, label = SOAK_START, SOAK_START + 3600, 'soak'
        windows = ['h00']
    else:
        start, end, label = SOAK_START, SOAK_START + SOAK_SECONDS + 3600, 'soak'
        windows = ['h%02d' % k for k in range(25)]
    report = {'runId': RUN, 'scope': args.action, 'generatedAt': iso(dt.datetime.now(dt.timezone.utc).timestamp()),
              'window': [iso(start), iso(end)], 'ingestionCutoff': iso(cutoff), 'verifierAppId': verifier.verifier['appId'],
              'latencyP99LimitSeconds': LATENCY_P99_LIMIT, 'collectors': {}}
    for host, (collector, event_type) in COLLECTORS.items():
        if host == 'linux':
            native, native_meta = firewall_native(results, label, cutoff if args.action == 'interim' else end)
            low, high = (0, 9000) if label == 'smoke' else (100000, 100000 + 896400)
            queue = {i for i in accepted(results, host) if re.fullmatch(r'a13-n\d{4}x\d{5}', i) and low <= index(i) < high}
        else:
            native, native_meta = windows_native(results, windows)
            queue = accepted(results, host)
        query_end = end if args.action != 'interim' else SOAK_START + 3600
        query_start = start - 120
        rows, hours, latency, hashes = sentinel(verifier, collector, event_type, query_start, query_end, cutoff)
        if host == 'linux':
            rows = {k: v for k, v in rows.items() if re.fullmatch(r'a13-n\d{4}x\d{5}', k) and low <= index(k) < high}
            if args.action == 'interim':
                # Later identities of the running segment are not in the interim expected prefix.
                limit = max((index(i) for i in native), default=-1)
                rows = {k: v for k, v in rows.items() if index(k) <= limit}
                queue = {i for i in queue if index(i) <= limit}
        else:
            # Windows identities are scoped by the DC's native windows; extra rows are kept as extras.
            pass
        result = compare(native, queue, rows)
        limit = LATENCY_P99_LIMIT[host]
        result.update(nativeDetail=native_meta, hours=hours, latencySeconds=latency, queryHashes=hashes,
                      latencyWithinLimit=bool(latency['p99'] is not None and latency['p99'] <= limit),
                      hoursAboveLatencyLimit=[h['from'] for h in hours if h['latencySeconds']['p99'] and h['latencySeconds']['p99'] > limit],
                      resources=resources(results, host, start, end))
        report['collectors'][host] = result
    report['health'], report['healthQueryHash'] = health(verifier, start, end)
    report['privacy'], report['privacyQueryHash'] = privacy(verifier, start - 120, end)
    report['alerts'] = alerts(verifier.state, start)
    text = json.dumps(report, indent=1, default=str)
    if args.out:
        args.out.write_text(text + '\n')
    summary = {h: {k: v for k, v in c.items() if k in ('native', 'accepted', 'sentinelDistinct', 'sentinelRows', 'duplicateRows',
                                                       'missingAtAccepted', 'missingAtSentinel', 'extraAtSentinel', 'exact', 'latencySeconds')}
               for h, c in report['collectors'].items()}
    print(json.dumps({'scope': args.action, 'summary': summary, 'privacy': report['privacy'], 'health': report['health'],
                      'alerts': report['alerts']}, indent=1, default=str))


def index(identity):
    port, source = identity[5:].split('x')
    return (int(port) - 4400) * 40000 + int(source) - 20000


if __name__ == '__main__':
    main()
