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
# docs/evidence/pilot-native-20261030) times two, applied to the whole-soak p99. Hours above the
# limit are listed, not gated.
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


def schedule(seconds, smoke=False):
    """The generators' segment schedule (sender-generator.sh, generator-windows.ps1):
    (offset, seconds, rate), 10/sec with a 60 s 100/sec burst at +2 h and every 4 h after,
    steady chunks of at most two hours."""
    bursts = [] if smoke else list(range(7200, seconds - 59, 14400))
    edges = sorted({0, seconds, *bursts, *(b + 60 for b in bursts)})
    segments = []
    for begin, end in zip(edges, edges[1:]):
        rate = 100 if begin in bursts else 10
        for at in range(begin, end, 7200):
            segments.append((at, min(7200, end - at), rate))
    return segments


def profile(label):
    """What a complete run of LABEL must contain: generator segments, events and native windows."""
    smoke = label == 'smoke'
    seconds = SMOKE_SECONDS if smoke else SOAK_SECONDS
    segments = schedule(seconds, smoke)
    windows = ['smoke'] if smoke else ['h%02d' % k for k in range(seconds // 3600 + 1)]
    return {'segments': segments, 'events': sum(n * r for _, n, r in segments),
            'first': 0 if smoke else 100000, 'windows': windows}


# syslog-host.py nft_ports: 40,000 source ports per destination port below index 2,000,000, then
# the extended source ports 1024..19999 (18,976 per port) used by the 72-hour re-soak.
EXTENDED_FIRST, EXTENDED_PER_PORT = 2000000, 18976
FIREWALL_ID = re.compile(r'a13-n\d{4}x\d{4,5}')


def firewall_id(n):
    if n < EXTENDED_FIRST:
        return 'a13-n{}x{}'.format(4400 + n // 40000, 20000 + n % 40000)
    e = n - EXTENDED_FIRST
    return 'a13-n{}x{}'.format(4400 + e // EXTENDED_PER_PORT, 1024 + e % EXTENDED_PER_PORT)


def firewall_ids(first, count):
    return {firewall_id(n) for n in range(first, first + count)}


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
    expected = profile(label)
    problems = []
    planned = [(expected['first'] + sum(n * r for _, n, r in expected['segments'][:k]), n * r, r)
               for k, (_, n, r) in enumerate(expected['segments'])]
    actual = [(s['first'], s['count'], s['rate']) for s in segments]
    if actual != planned[:len(actual)]:
        problems.append('segments-differ-from-profile')
    if not counter_ok:
        problems.append('native-counter-or-sent-mismatch')
    running = cutoff < start + total and label == 'soak'
    if not running and len(actual) != len(planned):
        problems.append('finished-segments-%d-of-%d' % (len(actual), len(planned)))
    if running:
        # Scheduled prefix of the running segment, 30 s behind the cutoff.
        offset = (segments[-1]['plannedStart'] - start + segments[-1]['count'] / segments[-1]['rate']) if segments else 0
        seconds = max(0, int(cutoff - 30 - (start + offset)))
        partial = seconds * 10  # the first soak segments are steady 10/sec until +2 h
        ids |= firewall_ids(next_first, partial)
    if not running and len(ids) != expected['events']:
        problems.append('native-%d-of-%d-planned-events' % (len(ids), expected['events']))
    return ids, {'segments': records, 'finishedSegments': len(records), 'plannedSegments': len(planned),
                 'plannedEvents': expected['events'], 'scheduledPrefixFromRunningSegment': partial,
                 'allFinishedSegmentsExact': counter_ok, 'expected': len(ids), 'problems': problems,
                 'complete': not problems and bool(ids)}


def dc_generator(results, label):
    """DC generator records: attempts per segment, all of which must fail with LDAP result 49."""
    records = [json.loads(path.read_text(encoding='utf-8-sig'))
               for path in sorted((results / 'hosts' / 'dc' / 'gen' / label).glob('segment-*.json'))]
    codes = {}
    for r in records:
        for code, count in r['ldapResultCodes'].items():
            codes[code] = codes.get(code, 0) + count
    clean = (all(r['allCallsCompleted'] and r['completed'] == r['attempted'] and not r['unexpectedSuccessfulLogons']
                 for r in records) and set(codes) <= {'49'})
    return {'segments': len(records), 'attempted': sum(r['attempted'] for r in records), 'ldapResultCodes': codes,
            'allSegmentsClean': clean}


def windows_native(results, windows, attempts=None):
    """Native 4625 identities from the DC's window exports. Identity is the ORIGINAL winevt- id
    (probe column 4), which the collector keeps. Column 1 is the probe's default-detector form:
    it masks some ids and can collide, so its counts are reported only as probeRedacted*. A
    missing window, an ids file that is short or lacks the original-id column, a duplicate
    original id, or a total that differs from ATTEMPTS makes the native set incomplete."""
    ids, meta, problems = set(), [], []
    duplicates = 0
    for name in windows:
        # Scheduled hourly export, else the on-demand export of the same window (dc-native-window.ps1).
        path = next((p for p in (results / 'hosts' / 'dc' / sub / (name + '.json') for sub in ('native', 'manual'))
                     if p.exists()), None)
        if path is None:
            meta.append({'window': name, 'missing': True})
            problems.append('missing-window-' + name)
            continue
        report = json.loads(path.read_text(encoding='utf-8-sig'))
        if re.fullmatch(r'h\d{2}', name):
            # An hourly export must cover exactly its hour; an empty or shifted window is not complete.
            since = SOAK_START + int(name[1:]) * 3600
            if (not report.get('since') or not report.get('until') or stamp_any(report['since']) != since
                    or stamp_any(report['until']) != since + 3600):
                problems.append('window-bounds-' + name)
        ids_path = path.with_name(name + '.ids') if path.parent.name == 'native' else path.with_name(name + '.json.ids')
        lines = [line for line in ids_path.read_text(encoding='utf-8-sig').splitlines() if line] if ids_path.exists() else []
        if len(lines) != report['selected']:
            problems.append('ids-file-incomplete-' + name)
        if any(line.count('\t') < 3 for line in lines):
            problems.append('no-original-id-column-' + name)
        window_ids = [line.split('\t')[3] for line in lines if line.count('\t') >= 3]
        distinct = set(window_ids)
        duplicates += len(window_ids) - len(distinct) + len(distinct & ids)
        ids |= distinct
        meta.append({'window': name, 'since': report['since'], 'until': report.get('until'), 'records': report['selected'],
                     'distinctOriginalIds': len(distinct), 'originalIdSetSha256': digest(distinct),
                     'probeRedactedDistinct': report['distinct'], 'probeRedactedDuplicates': report['duplicateIdentities'],
                     'probeRedactionChangedIds': report['redactionChangedIds'],
                     'probeRedactedSetSha256': report['identitySetSha256']})
    if duplicates:
        problems.append('duplicate-original-ids')
    if attempts is not None and len(ids) != attempts:
        problems.append('native-%d-differs-from-%d-attempts' % (len(ids), attempts))
    return ids, {'windows': meta, 'expected': len(ids), 'originalIdDuplicates': duplicates, 'problems': problems,
                 'complete': not problems and bool(ids)}


def accepted(results, host):
    """Accepted union as {event id: time}. Linux records the queue's received_at. The WEC union
    records the time the union first saw the id (column 2, within 30 minutes of acceptance), or
    receivedAt in column 3 from probe revisions after this soak."""
    if host == 'linux':
        path = results / 'hosts' / 'linux' / 'accepted.tsv.gz'
        lines = gzip.open(path, 'rt').read().splitlines() if path.exists() else []
    else:
        path = results / 'hosts' / 'wec' / 'accepted.tsv'
        lines = path.read_text(encoding='utf-8-sig').splitlines() if path.exists() else []
    result = {}
    for line in lines:
        if line:
            parts = line.split('\t')
            result[parts[0]] = parts[2] if len(parts) > 2 and parts[2] else (parts[1] if len(parts) > 1 else '')
    return result


def scope_accepted(host, union, label, last_index=None):
    """The accepted ids that belong to LABEL, chosen by source and window, never by the native
    set: firewall by sequence range (cut at LAST_INDEX for the interim), WEC by winevt- prefix
    and acceptance time (smoke before the soak start, soak from it)."""
    if host == 'linux':
        expected = profile(label)
        low, high = expected['first'], expected['first'] + expected['events']
        if last_index is not None:
            high = min(high, last_index + 1)
        return {i for i in union if FIREWALL_ID.fullmatch(i) and low <= index(i) < high}
    low, high = (SMOKE_START, SOAK_START) if label == 'smoke' else (SOAK_START, float('inf'))
    return {i for i, at in union.items() if i.startswith('winevt-') and at and low <= stamp_any(at) < high}


def stamp_any(value):
    """SQLite 'YYYY-MM-DD HH:MM:SS[.f]' (UTC) or ISO 8601 with an offset."""
    value = value.strip()
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?', value):
        value += 'Z'
    return qf.stamp(value.replace(' ', 'T', 1))


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
                                         headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
                                                  'Cache-Control': 'no-cache'})
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


def sentinel(verifier, collector, event_type, start, end, cutoff, chunk=3600, keep=None):
    """Every row of the collector's event type with TimeGenerated in [start, end), per chunk.
    KEEP selects the reported identities before any count or latency is computed, so hourly and
    overall statistics describe exactly the reconciled set (the query bounds stay padded)."""
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
        if keep is not None:
            result = [row for row in result if keep(row['EventId'])]
        latencies = []
        for row in result:
            if row['EventId'] in rows:
                # An id whose copies span two chunks: one identity, all copies, earliest times.
                kept = rows[row['EventId']]
                kept['Copies'] += row['Copies']
                kept['Generated'] = min(kept['Generated'], row['Generated'], key=stamp)
                kept['FirstIngested'] = min(kept['FirstIngested'], row['FirstIngested'], key=stamp)
                continue
            rows[row['EventId']] = row
            latencies.append(stamp(row['FirstIngested']) - stamp(row['Generated']))
        hours.append({'from': iso(t), 'to': iso(u), 'distinct': len(result), 'rows': sum(r['Copies'] for r in result),
                      'latencySeconds': quantiles(latencies)})
        t = u
    # Recomputed after merging, so an id spanning two chunks uses its earliest times once.
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


def arm_list(url, runner=None):
    """Every item of an ARM list, following nextLink. Any failure raises: an unread page must
    never read as 'no alerts'."""
    runner = runner or (lambda u: subprocess.run(['az', 'rest', '--method', 'get', '--url', u, '--only-show-errors',
                                                  '--output', 'json'], capture_output=True, text=True, timeout=120))
    items, pages = [], 0
    while url:
        pages += 1
        if pages > 100:
            raise RuntimeError('Too many alert pages')
        result = runner(url)
        if result.returncode:
            raise RuntimeError('Alert or incident query failed; output suppressed')
        page = json.loads(result.stdout)
        items.extend(page.get('value', []))
        url = page.get('nextLink')
    return items


def alerts(state, start, end, runner=None):
    """Azure Monitor alert instances and Sentinel incidents in the run's resource group (operator
    read). Each item records whether it was active at any time inside [start, end)."""
    base = 'https://management.azure.com/subscriptions/' + qf.SUBSCRIPTION
    out = {}
    for name, url in (('alerts', base + '/providers/Microsoft.AlertsManagement/alerts?api-version=2019-05-05-preview'
                       '&targetResourceGroup=' + state['group'] + '&timeRange=30d'),
                      ('incidents', 'https://management.azure.com' + state['workspaceResourceId']
                       + '/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01')):
        listed = []
        for item in arm_list(url, runner):
            props = item.get('properties', {})
            essentials = props.get('essentials') or {}
            started = essentials.get('startDateTime') or props.get('createdTimeUtc')
            resolved = essentials.get('monitorConditionResolvedDateTime') or props.get('closedTimeUtc')
            began = stamp(started) if started else None
            stopped = stamp(resolved) if resolved else None
            listed.append({'name': (essentials.get('alertRule') or item.get('name', '')).split('/')[-1],
                           'state': essentials.get('monitorCondition') or props.get('status'),
                           'startedAt': started, 'resolvedAt': resolved,
                           'activeDuringRun': began is not None and began < end and (stopped is None or stopped >= start)})
        out[name] = listed
    out['activeDuringRun'] = sum(item['activeDuringRun'] for kind in ('alerts', 'incidents') for item in out[kind])
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


GROWTH_FROM_HOUR, GROWTH_TO_HOUR, GROWTH_LIMIT_PERCENT = 3, 24, 10


def load_samples(path):
    path = Path(path)
    return [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()] if path.exists() else []


def resources(samples, host, start, end):
    """Resource analysis of the samples in [start, end). Criterion 3 as registered before the run:
    least-squares slopes over hours 3 to 24 of the workload, flat when the 30-day projection is
    under 10% of the mean. Pass the workload window; analyse the delivery drain separately."""
    rows = [r for r in samples if start <= stamp(r['at']) < end]
    # Process metrics come first in a sample; a later status failure keeps them (error recorded).
    good = [r for r in rows if r.get('process')]
    status_rows = [r for r in good if r.get('queue')]
    def series(get, warm=GROWTH_FROM_HOUR):
        return slope([((stamp(r['at']) - start) / 3600, get(r)) for r in good
                      if warm <= (stamp(r['at']) - start) / 3600 < GROWTH_TO_HOUR])
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
    for r in status_rows:
        for job, value in (r.get('jobs') or {}).items():
            if value and value.get('lastRunAt'):
                jobs.setdefault(job, set()).add((value['lastRunAt'], value['lastState']))
    growth = {'memoryBytes': series(mem), 'handlesOrFds': series(handles),
              'threads': series(lambda r: r['process']['threads']), 'queueDbPlusWalBytes': series(store)}
    # Registered rule: the 30-day projection is under 10% of the mean. A falling series is not growth.
    flat = {k: v is not None and v['thirtyDayProjectionPercentOfMean'] is not None
            and v['thirtyDayProjectionPercentOfMean'] < GROWTH_LIMIT_PERCENT for k, v in growth.items()}
    hourly = {}
    for r in good:
        hourly.setdefault(int((stamp(r['at']) - start) // 3600), []).append(r['process']['cpuSeconds'])
    return {
        'window': [iso(start), iso(end)], 'growthHours': [GROWTH_FROM_HOUR, GROWTH_TO_HOUR],
        'criterion3': {'flat': flat, 'pass': bool(good) and all(flat.values())},
        'cpuSecondsPerHour': [round(max(v) - min(v), 1) for _, v in sorted(hourly.items())],
        'samples': len(rows), 'samplesWithoutProcess': len(rows) - len(good), 'samplesWithoutStatus': len(rows) - len(status_rows),
        'sampleErrors': sorted({r.get('error') for r in rows if r.get('error')}), 'processIdentities': len(pids), 'bootIds': len(boots),
        'serviceRestartCounter': restarts,
        'maximumSampleGapSeconds': max((stamp(b['at']) - stamp(a['at']) for a, b in zip(rows, rows[1:])), default=None),
        **growth, 'memoryBytesFromStart': series(mem, 0),
        'walBytes': series(lambda r: r['files'].get('queue.db-wal', 0)),
        'cpuPercentOfOneCore': quantiles(cpu),
        'peakPending': max((r['queue']['pending'] for r in status_rows), default=None),
        'peakOldestUndeliveredAgeSeconds': max((r['queue']['oldestAgeSeconds'] for r in status_rows), default=None),
        'minimumDiskAvailableBytes': min((r['disk']['availableBytes'] for r in good), default=None),
        'statuses': sorted({r.get('status') for r in status_rows}, key=str),
        'jobRuns': {job: {'runs': len(v), 'states': sorted({s for _, s in v}, key=str), 'last': max(v)[0]} for job, v in jobs.items()},
        'deliveryFailureCodes': sorted({(r.get('delivery') or {}).get('lastFailureCode') for r in status_rows}, key=str),
    }


def compare(native, queue, rows, native_complete=True):
    """Exact only when the native set is complete and non-empty and the independently scoped
    accepted and Sentinel sets both equal it: nothing missing and nothing extra at either stage.
    Duplicate Sentinel rows are counted, not failed (at-least-once)."""
    destination = set(rows)
    copies = sum(r['Copies'] for r in rows.values())
    return {'native': len(native), 'accepted': len(queue), 'sentinelDistinct': len(destination),
            'sentinelRows': copies, 'duplicateRows': copies - len(destination),
            'missingAtAccepted': len(native - queue), 'extraAtAccepted': len(queue - native),
            'missingAtSentinel': len(native - destination), 'extraAtSentinel': len(destination - native),
            'nativeComplete': native_complete,
            'nativeSha256': digest(native), 'acceptedSha256': digest(queue), 'sentinelSha256': digest(destination),
            'exact': bool(native) and native_complete and native == queue == destination}


def analyse_series(series_dir):
    """Resource results recomputed from committed evidence series (no identity lists needed):
    the workload window [start, start + 24 h) and, separately, the delivery drain (+1 h)."""
    out = {'growthRule': {'hours': [GROWTH_FROM_HOUR, GROWTH_TO_HOUR], 'thirtyDayProjectionPercentOfMeanBelow': GROWTH_LIMIT_PERCENT}}
    for host, name in (('linux', 'linux-samples.jsonl'), ('windows', 'wec-samples.jsonl')):
        samples = load_samples(Path(series_dir) / name)
        drain = resources(samples, host, SOAK_START + SOAK_SECONDS, SOAK_START + SOAK_SECONDS + 3600)
        # The drain hour has no hours-3-to-24 series; report its metrics without a growth verdict.
        for key in ('criterion3', 'growthHours', 'memoryBytes', 'handlesOrFds', 'threads', 'queueDbPlusWalBytes',
                    'memoryBytesFromStart', 'walBytes'):
            drain.pop(key, None)
        out[host] = {'workload': resources(samples, host, SOAK_START, SOAK_START + SOAK_SECONDS), 'drain': drain}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('fetch', 'smoke', 'interim', 'final', 'series'))
    parser.add_argument('--lab-dir', type=Path)
    parser.add_argument('--series-dir', type=Path, help='series: the committed evidence series directory')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--cutoff', type=float, help='ingestion cutoff epoch (default now)')
    parser.add_argument('--native-windows', help='comma-separated DC export names (default per scope)')
    args = parser.parse_args()
    if args.action == 'series':
        text = json.dumps(analyse_series(args.series_dir), indent=1)
        if args.out:
            args.out.write_text(text + '\n')
        print(text)
        return
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
        windows = profile('soak')['windows']
    if args.native_windows:
        windows = args.native_windows.split(',')
    report = {'runId': RUN, 'scope': args.action, 'generatedAt': iso(dt.datetime.now(dt.timezone.utc).timestamp()),
              'window': [iso(start), iso(end)], 'ingestionCutoff': iso(cutoff), 'verifierAppId': verifier.verifier['appId'],
              'latencyP99LimitSeconds': LATENCY_P99_LIMIT, 'collectors': {}}
    for host, (collector, event_type) in COLLECTORS.items():
        if host == 'linux':
            # Interim: exactly the first hour's scheduled identities (the running segment's prefix).
            native, native_meta = firewall_native(results, label, SOAK_START + 3630 if args.action == 'interim' else end)
            prefix = max((index(i) for i in native), default=-1) if args.action == 'interim' else None
            queue = scope_accepted(host, accepted(results, host), label, prefix)
            low, high = profile(label)['first'], profile(label)['first'] + profile(label)['events']
        else:
            generator = dc_generator(results, label)
            final = args.action != 'interim'
            native, native_meta = windows_native(results, windows, generator['attempted'] if final else None)
            native_meta['generator'] = generator
            if final and (generator['segments'] != len(profile(label)['segments'])
                          or generator['attempted'] != profile(label)['events'] or not generator['allSegmentsClean']):
                native_meta['problems'].append('dc-generator-differs-from-profile')
                native_meta['complete'] = False
            union = accepted(results, host)
            queue = scope_accepted(host, union, label)
            if not final:
                # Accepted within the first hour plus one union interval.
                queue = {i for i in queue if stamp_any(union[i]) < SOAK_START + 3600 + 1800}
        query_end = end if args.action != 'interim' else SOAK_START + 3600 + (300 if host == 'linux' else 0)
        query_start = start - 120
        keep = None
        if host == 'linux':
            # The scoped sequence range, cut at the interim prefix: later identities of the
            # running segment are neither expected nor counted in latency.
            top = high if args.action != 'interim' else min(high, max((index(i) for i in native), default=-1) + 1)
            keep = lambda k, low=low, top=top: bool(FIREWALL_ID.fullmatch(k)) and low <= index(k) < top
        rows, hours, latency, hashes = sentinel(verifier, collector, event_type, query_start, query_end, cutoff, keep=keep)
        # The interim compares a running prefix; completeness gates smoke and final only.
        result = compare(native, queue, rows, native_meta['complete'] or args.action == 'interim')
        limit = LATENCY_P99_LIMIT[host]
        result.update(nativeDetail=native_meta, hours=hours, latencySeconds=latency, queryHashes=hashes,
                      latencyWithinLimit=bool(latency['p99'] is not None and latency['p99'] <= limit),
                      hoursAboveLatencyLimit=[h['from'] for h in hours if h['latencySeconds']['p99'] and h['latencySeconds']['p99'] > limit],
                      resources=resources(load_samples(results / 'hosts' / ('linux' if host == 'linux' else 'wec') / 'samples.jsonl'),
                                          host, start, SOAK_START + SOAK_SECONDS if args.action == 'final' else end))
        report['collectors'][host] = result
    report['health'], report['healthQueryHash'] = health(verifier, start, end)
    report['privacy'], report['privacyQueryHash'] = privacy(verifier, start - 120, end)
    report['alerts'] = alerts(verifier.state, start, end)
    text = json.dumps(report, indent=1, default=str)
    if args.out:
        args.out.write_text(text + '\n')
    summary = {h: {k: v for k, v in c.items() if k in ('native', 'accepted', 'sentinelDistinct', 'sentinelRows', 'duplicateRows',
                                                       'missingAtAccepted', 'extraAtAccepted', 'missingAtSentinel',
                                                       'extraAtSentinel', 'nativeComplete', 'exact', 'latencySeconds')}
               for h, c in report['collectors'].items()}
    print(json.dumps({'scope': args.action, 'summary': summary, 'privacy': report['privacy'], 'health': report['health'],
                      'alerts': report['alerts']}, indent=1, default=str))


def index(identity):
    port, source = map(int, identity[5:].split('x'))
    if source < 20000:
        return EXTENDED_FIRST + (port - 4400) * EXTENDED_PER_PORT + source - 1024
    return (port - 4400) * 40000 + source - 20000


if __name__ == '__main__':
    main()
