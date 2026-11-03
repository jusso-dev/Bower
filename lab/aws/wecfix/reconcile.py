#!/usr/bin/env python3
"""wecfix reconciliation: native = accepted = Sentinel identities, latency and CPU per WEC.

Reads the run bucket's metadata-only results (DC native identity windows, each WEC's accepted
union and per-minute samples) and queries Sentinel with the separate verifier identity
(lab/aws/monitoring/query-firewall.py: isolated Azure CLI cache, no persisted tokens).
Writes counts, SHA-256 set digests, latency quantiles and CPU series only; identities stay in
the private lab directory.

  reconcile.py --lab-dir /tmp/<run> --start EPOCH --end EPOCH --out result.json \
      --collector Wec=<run>-Wec --collector Wec2=<run>-Wec2 [--upgrade-at EPOCH]
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import urllib.request

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('query_firewall', HERE.parent / 'monitoring' / 'query-firewall.py')
qf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qf)
PILOT_WEC_P99_LIMIT = 18.16  # seconds: 2 x the pilot's connected WEC p99 (07 soak criterion 4)


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def digest(ids):
    return hashlib.sha256('\n'.join(sorted(ids)).encode('ascii')).hexdigest()


def quantiles(values):
    values = sorted(values)
    pick = lambda f: round(values[max(0, math.ceil(len(values) * f) - 1)], 3) if values else None
    return {'count': len(values), 'p50': pick(.5), 'p95': pick(.95), 'p99': pick(.99),
            'max': round(values[-1], 3) if values else None}


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
        request = urllib.request.Request(
            'https://api.loganalytics.io/v1/workspaces/' + self.state['workspaceId'] + '/query',
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


def sentinel(verifier, collector, start, end, chunk=1800):
    """Distinct 4625 identities of one collector with TimeGenerated in [start, end)."""
    rows, hours, hashes = {}, [], []
    t = start
    while t < end:
        u = min(end, t + chunk)
        text = ('BowerSecurity_CL\n| where TimeGenerated >= datetime({a}) and TimeGenerated < datetime({b})\n'
                '| where CollectorId == "{c}" and EventType == "authentication_failure"\n'
                '| summarize Copies=count(), Generated=min(TimeGenerated), FirstIngested=min(ingestion_time()) by EventId\n'
                '| take 400001').format(a=iso(t), b=iso(u), c=collector)
        result, query_hash = verifier.query(text)
        if len(result) > 400000:
            raise ValueError('Chunk too large')
        hashes.append(query_hash)
        latencies = []
        for row in result:
            if row['EventId'] in rows:
                rows[row['EventId']]['Copies'] += row['Copies']
                continue
            rows[row['EventId']] = row
            latencies.append(qf.stamp(row['FirstIngested']) - qf.stamp(row['Generated']))
        hours.append({'from': iso(t), 'to': iso(u), 'distinct': len(result),
                      'rows': sum(r['Copies'] for r in result), 'latencySeconds': quantiles(latencies)})
        t = u
    latencies = [qf.stamp(r['FirstIngested']) - qf.stamp(r['Generated']) for r in rows.values()]
    return rows, hours, quantiles(latencies), hashes


def native(lab, start, end):
    ids = set()
    windows = []
    for report in sorted((lab / 'results' / 'dc').glob('*.json')):
        meta = json.loads(report.read_text())
        since, until = qf.stamp(meta['since']), qf.stamp(meta['until'])
        if since < start or until > end:
            continue
        for line in Path(str(report) + '.ids').read_text().splitlines():
            if line:
                ids.add(line.split('\t')[3])  # the original id: collectors keep it
        windows.append({'name': report.stem, 'since': meta['since'], 'until': meta['until'],
                        'selected': meta['selected'], 'distinct': meta['distinct']})
    return ids, windows


def accepted(lab, host):
    ids = set()
    for line in (lab / 'results' / host / 'accepted.tsv').read_text(encoding='utf-8-sig').splitlines():
        if line.startswith('winevt-'):
            ids.add(line.split('\t')[0])
    return ids


def samples(lab, host):
    rows = []
    for line in (lab / 'results' / host / 'samples.jsonl').read_text(encoding='utf-8-sig').splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get('process'):
            rows.append(row)
    return rows


def resources(rows, start, end, upgrade_at=None):
    """CPU per hour (process, user, kernel, Event Log service), reader lag and source counters."""
    rows = [r for r in rows if start - 120 <= qf.stamp(r['at']) <= end + 120]
    hours = []
    t = start
    while t < end:
        u = min(end, t + 3600)
        inside = [r for r in rows if t <= qf.stamp(r['at']) <= u]
        pairs = [(a, b) for a, b in zip(inside, inside[1:]) if a['process']['pid'] == b['process']['pid']]
        seconds = sum(qf.stamp(b['at']) - qf.stamp(a['at']) for a, b in pairs)
        rate = lambda get: round(sum(get(b) - get(a) for a, b in pairs) / seconds * 3600, 1) if seconds else None
        windows = [(r.get('windowsEventLog') or [{}])[0] for r in inside]
        lags = [r['forwardedEvents']['records'] - (w.get('bookmarkRecordId') or 0) for r, w in zip(inside, windows)]
        hours.append({
            'from': iso(t), 'to': iso(u), 'samples': len(inside),
            'cpuSecondsPerHour': rate(lambda r: r['process']['cpuSeconds']),
            'userSecondsPerHour': rate(lambda r: r['process'].get('userSeconds', 0)),
            'kernelSecondsPerHour': rate(lambda r: r['process'].get('kernelSeconds', 0)),
            'eventLogServiceCpuSecondsPerHour': rate(lambda r: r['eventLogService']['cpuSeconds']),
            'readerLagRecords': {'max': max(lags) if lags else None, 'p50': sorted(lags)[len(lags) // 2] if lags else None},
            'queueRowsMax': max((r['queue']['delivered'] for r in inside), default=None),
            'forwardedEventsRecords': inside[-1]['forwardedEvents']['records'] if inside else None,
            'states': sorted({w.get('state') for w in windows if w.get('state')}),
            'pids': sorted({r['process']['pid'] for r in inside}),
        })
        t = u
    last = (rows[-1].get('windowsEventLog') or [{}])[0] if rows else {}
    return {'hours': hours, 'finalSourceCounters': {k: last.get(k) for k in (
        'eventsRead', 'queued', 'duplicates', 'retries', 'submitFailures', 'readErrors', 'gaps', 'resets', 'cursorConflicts')},
        'upgradeAt': iso(upgrade_at) if upgrade_at else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--lab-dir', type=Path, required=True)
    parser.add_argument('--start', type=int, required=True)
    parser.add_argument('--end', type=int, required=True)
    parser.add_argument('--collector', action='append', required=True, help='HOST=CollectorId')
    parser.add_argument('--upgrade-at', type=int, help='epoch the new build was installed on Wec')
    parser.add_argument('--window', action='append', default=[], help='NAME=FROM:TO (epochs) for extra latency quantiles')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    lab = args.lab_dir
    windows_named = [(w.split('=', 1)[0], *map(int, w.split('=', 1)[1].split(':'))) for w in args.window]
    expected, windows = native(lab, args.start, args.end)
    verifier = Verifier(lab / 'azure')
    result = {'run': lab.name, 'start': iso(args.start), 'end': iso(args.end),
              'native': {'distinct': len(expected), 'sha256': digest(expected), 'windows': windows},
              'pilotWecP99LimitSeconds': PILOT_WEC_P99_LIMIT, 'collectors': {}}
    for item in args.collector:
        host, collector = item.split('=', 1)
        queue = accepted(lab, host)
        rows, hours, latency, hashes = sentinel(verifier, collector, args.start, args.end)
        destination = set(rows)
        # The union also holds events generated outside the window; those are reported, not compared.
        in_window_queue = {i for i in queue if i in expected or i in destination}
        result['collectors'][host] = {
            'collectorId': collector,
            'accepted': {'distinct': len(in_window_queue), 'sha256': digest(in_window_queue),
                         'outsideWindow': len(queue - in_window_queue)},
            'sentinel': {'distinct': len(destination), 'rows': sum(r['Copies'] for r in rows.values()),
                         'duplicateRows': sum(r['Copies'] - 1 for r in rows.values()), 'sha256': digest(destination),
                         'queryHashes': hashes},
            'exact': expected == in_window_queue == destination,
            'missingFromAccepted': len(expected - in_window_queue), 'extraInAccepted': len(in_window_queue - expected),
            'missingFromSentinel': len(expected - destination), 'extraInSentinel': len(destination - expected),
            'latencySeconds': latency,
            'latencyPassesPilotLimit': latency['p99'] is not None and latency['p99'] <= PILOT_WEC_P99_LIMIT,
            'latencyByWindow': hours,
            'latencyByNamedWindow': {name: quantiles([qf.stamp(r['FirstIngested']) - qf.stamp(r['Generated']) for r in rows.values()
                                                      if a <= qf.stamp(r['Generated']) < b])
                                     for name, a, b in windows_named},
            'resources': resources(samples(lab, host), args.start, args.end, args.upgrade_at if host == 'Wec' else None),
        }
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({h: {k: c[k] for k in ('exact', 'latencySeconds', 'latencyByNamedWindow')} for h, c in result['collectors'].items()}, indent=1))


if __name__ == '__main__':
    main()
