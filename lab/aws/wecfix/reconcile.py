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
import re
import stat
import subprocess
import sys
import tempfile
import unicodedata
import urllib.request

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('query_firewall', HERE.parent / 'monitoring' / 'query-firewall.py')
qf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qf)
PILOT_WEC_P99_LIMIT = 18.16  # seconds: 2 x the pilot's connected WEC p99 (07 soak criterion 4)
WEC_ID = re.compile(r'winevt-[0-9a-f]{32}\Z')
TSV_FORBIDDEN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029]')


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def write_report(path, result):
    """Replace a report atomically with an owner-only file, leaving no partial JSON."""
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def path_argument(arguments, option):
    """Identify one explicit path option without validating other arguments."""
    outputs = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == '--':
            break
        if argument == option:
            value = arguments[index + 1] if index + 1 < len(arguments) and not arguments[index + 1].startswith('-') else None
            outputs.append(value)
            if value is not None:
                index += 1
        elif argument.startswith(option + '='):
            outputs.append(argument[len(option) + 1:] or None)
        index += 1
    return (Path(outputs[0]) if len(outputs) == 1 and outputs[0] else None), len(outputs)


def verify_disjoint_report(lab, output):
    """Reject reports in or aliased to the input tree before touching either path."""
    try:
        root = lab.resolve(strict=True)
        if not root.is_dir():
            raise ValueError('Lab input is not a directory')
        destination = output.resolve(strict=False)
        if destination == root or root in destination.parents:
            raise ValueError('Report is inside the lab input tree')
        try:
            target = destination.stat()
        except FileNotFoundError:
            target = None
        if target is not None and stat.S_ISDIR(target.st_mode):
            raise ValueError('Report path is a directory')
        ancestor = destination.parent
        while not ancestor.exists():
            if ancestor == ancestor.parent:
                raise ValueError('Cannot find report parent')
            ancestor = ancestor.parent
        parent_stat = ancestor.stat()
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise ValueError('Report parent is not a directory')
        parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
        root_stat = root.stat()
        if (root_stat.st_dev, root_stat.st_ino) == parent_identity:
            raise ValueError('Report parent aliases lab input')

        def onerror(_error):
            raise ValueError('Cannot inspect lab input tree')

        for current, directories, files in os.walk(root, followlinks=False, onerror=onerror):
            for name in directories + files:
                entry = Path(current) / name
                item = entry.lstat()
                if stat.S_ISLNK(item.st_mode):
                    resolved = entry.resolve(strict=False)
                    if resolved == destination or resolved in destination.parents:
                        raise ValueError('Lab input has an ambiguous symlink')
                    try:
                        item = entry.stat()
                    except FileNotFoundError:
                        continue
                    if stat.S_ISDIR(item.st_mode):
                        raise ValueError('Lab input has an ambiguous symlink')
                if target is not None and (item.st_dev, item.st_ino) == (target.st_dev, target.st_ino):
                    raise ValueError('Report aliases lab input')
                if stat.S_ISDIR(item.st_mode) and (item.st_dev, item.st_ino) == parent_identity:
                    raise ValueError('Report parent aliases lab input')
    except (OSError, RuntimeError) as error:
        raise ValueError('Cannot verify report and lab input are disjoint') from error


def digest(ids):
    return hashlib.sha256('\n'.join(sorted(ids)).encode('ascii')).hexdigest()


def quantiles(values):
    values = sorted(values)
    pick = lambda f: round(values[max(0, math.ceil(len(values) * f) - 1)], 3) if values else None
    return {'count': len(values), 'negativeSamples': sum(value < 0 for value in values),
            'p50': pick(.5), 'p95': pick(.95), 'p99': pick(.99),
            'max': round(values[-1], 3) if values else None}


def tsv_lines(path, encoding='utf-8'):
    """Split on LF only and reject hidden separators and other forbidden controls."""
    with path.open('r', encoding=encoding, newline='') as stream:
        data = stream.read()
    terminated = data.endswith('\n')
    lines = data.split('\n')
    if lines and not lines[-1]:
        lines.pop()  # A single final newline is the normal export format.
    for index, line in enumerate(lines):
        if line.endswith('\r'):
            if index == len(lines) - 1 and not terminated:
                raise ValueError('Bare carriage return in identity export')
            line = line[:-1]  # Strip the CR only when it is followed by LF.
        if '\r' in line or TSV_FORBIDDEN.search(line):
            raise ValueError('Invalid control character in identity export')
        yield line


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
        if meta.get('until') is None:
            windows.append({'name': report.stem, 'since': meta.get('since'), 'until': None,
                            'problems': ['native-window-open-ended']})
            continue
        since, until = qf.stamp(meta['since']), qf.stamp(meta['until'])
        if since < start or until > end:
            continue
        problems = []
        if meta.get('kind') != 'native' or meta.get('channel') != 'Security':
            problems.append('unexpected-native-export')
        try:
            started = qf.stamp(meta['captureStartedAt'])
            captured = qf.stamp(meta['capturedAt'])
            if started < until or captured < started:
                problems.append('native-captured-before-window-completed')
        except (KeyError, TypeError, ValueError, OverflowError):
            problems.append('native-capture-time-unproven')
        redacted_ids = []
        original_ids = []
        for line in tsv_lines(Path(str(report) + '.ids')):
            fields = line.split('\t')
            if len(fields) != 4 or not WEC_ID.fullmatch(fields[3]):
                raise ValueError('Invalid native identity row')
            try:
                int(fields[1]); int(fields[2])
            except ValueError as error:
                raise ValueError('Invalid native record position') from error
            redacted_ids.append(fields[0])
            original_ids.append(fields[3])
        if ids.intersection(original_ids):
            problems.append('native-identities-overlap-windows')
        ids.update(original_ids)
        redacted_set = set(redacted_ids)
        changed = sum(redacted != original for redacted, original in zip(redacted_ids, original_ids))
        measured = {'selected': len(original_ids), 'distinct': len(redacted_set),
                    'duplicateIdentities': len(redacted_ids) - len(redacted_set), 'redactionChangedIds': changed}
        if any(type(meta.get(key)) is not int or meta[key] != value for key, value in measured.items()):
            problems.append('native-counts-mismatch')
        examined, unselected = meta.get('examined'), meta.get('unselected')
        if (type(examined) is not int or type(unselected) is not int or unselected < 0
                or examined < len(original_ids) + unselected):
            problems.append('native-examination-counts-invalid')
        if changed or measured['duplicateIdentities'] or any(not WEC_ID.fullmatch(value) for value in redacted_ids):
            problems.append('native-identities-changed-or-duplicated')
        native_hash = hashlib.sha256('\n'.join(sorted(redacted_set)).encode('utf-8')).hexdigest()
        if meta.get('identitySetSha256') != native_hash:
            problems.append('native-digest-mismatch')
        windows.append({'name': report.stem, 'since': meta['since'], 'until': meta['until'],
                        'selected': meta.get('selected'), 'distinct': meta.get('distinct'),
                        'problems': problems})
    return ids, windows


def native_window_complete(windows, start, end):
    """Require source exports to cover the whole requested generation interval."""
    if any(window.get('problems') for window in windows):
        return False
    covered = start
    for since, until in sorted((qf.stamp(w['since']), qf.stamp(w['until'])) for w in windows):
        if until <= since or since > covered:
            return False
        covered = max(covered, until)
    return start < end and covered >= end


def accepted(lab, host):
    ids = {}
    for line in tsv_lines(lab / 'results' / host / 'accepted.tsv', encoding='utf-8-sig'):
        fields = line.split('\t')
        if not 2 <= len(fields) <= 4 or not fields[0] or any(unicodedata.category(char) == 'Cc' for char in fields[0]):
            raise ValueError('Invalid accepted identity row')
        try:
            qf.stamp(fields[1])
            if len(fields) >= 3:
                qf.stamp(fields[2])
        except (ValueError, TypeError, OverflowError) as error:
            raise ValueError('Invalid accepted observation timestamp') from error
        try:
            generated_at = qf.stamp(fields[3]) if len(fields) > 3 and fields[3] else None
        except (ValueError, TypeError, OverflowError) as error:
            raise ValueError('Invalid accepted generation timestamp') from error
        if fields[0].startswith('winevt-'):
            if not WEC_ID.fullmatch(fields[0]):
                raise ValueError('Invalid Windows accepted identity')
            # The fourth field is the source event's normalized generation time.
            # Older queue-union exports contain only intake/observation times.
            event_id = fields[0]
            if event_id in ids and ids[event_id] != generated_at:
                raise ValueError('Conflicting accepted timestamps for an event identity')
            ids[event_id] = generated_at
    return ids


def reconcile_identities(expected, queue, destination, start, end):
    """Compare identities without assuming an unmatched accepted ID is outside the window.

    Scope each accepted identity by its own source generation time. Old exports and
    invalid timestamps cannot establish that scope, even when the identity appears in
    another set, so they remain indeterminate and prevent an exact pass.
    """
    in_window = {event_id for event_id, generated_at in queue.items()
                 if generated_at is not None and start <= generated_at < end}
    indeterminate = {event_id for event_id, generated_at in queue.items() if generated_at is None}
    outside = set(queue) - in_window - indeterminate
    return {
        'accepted': in_window,
        'indeterminate': indeterminate,
        'outside': outside,
        'exact': not indeterminate and expected == in_window == destination,
    }


def samples(lab, host):
    rows, invalid = [], []
    last_time = None
    def reject_constant(_):
        raise ValueError('Non-finite sample number')
    for number, line in enumerate((lab / 'results' / host / 'samples.jsonl').read_text(encoding='utf-8-sig').splitlines(), 1):
        try:
            row = json.loads(line, parse_constant=reject_constant)
        except ValueError:
            invalid.append({'line': number, 'time': None, 'reason': 'invalid-json'})
            continue
        try:
            time = qf.stamp(row.get('at')) if isinstance(row, dict) else None
        except (TypeError, ValueError, OverflowError):
            time = None
        if time is not None and last_time is not None and time <= last_time:
            invalid.append({'line': number, 'time': time, 'reason': 'nonmonotonic-sample-time'})
            continue
        if time is not None:
            last_time = time
        if (not isinstance(row, dict) or not isinstance(row.get('process'), dict) or row.get('error')
                or type(row['process'].get('pid')) is not int or row['process']['pid'] <= 0
                or type(row['process'].get('cpuSeconds')) not in (int, float)
                or not math.isfinite(row['process']['cpuSeconds']) or row['process']['cpuSeconds'] < 0
                or not isinstance(row.get('queue'), dict) or type(row['queue'].get('delivered')) is not int
                or row['queue']['delivered'] < 0
                or not isinstance(row.get('forwardedEvents'), dict)
                or type(row['forwardedEvents'].get('records')) is not int or row['forwardedEvents']['records'] < 0
                or not isinstance(row.get('windowsEventLog'), list)
                or any(not isinstance(item, dict) for item in row['windowsEventLog'])):
            invalid.append({'line': number, 'time': time, 'reason': 'incomplete-sample'})
            continue
        try:
            qf.stamp(row['at'])
            qf.stamp(row['process']['startedAt'])
        except (KeyError, TypeError, ValueError, OverflowError):
            invalid.append({'line': number, 'time': time, 'reason': 'invalid-timestamp'})
            continue
        rows.append(row)
    return rows, invalid


def capture_evidence(lab, host, sample_state, sample_rows, invalid_samples):
    """Describe available observations; they cannot prove complete queue capture."""
    root = lab / 'results' / host
    union_path, error_path = root / 'union.jsonl', root / 'errors.log'
    union = {'state': 'missing', 'successfulSnapshots': 0}
    if union_path.exists():
        union['state'] = 'empty'
        try:
            for line in union_path.read_text(encoding='utf-8-sig').splitlines():
                row = json.loads(line)
                if not isinstance(row, dict) or row.get('kind') != 'queue-union':
                    raise ValueError('Invalid union snapshot')
                qf.stamp(row['capturedAt'])
                if type(row.get('unionAfter')) is not int or row['unionAfter'] < 0:
                    raise ValueError('Invalid union count')
                union['successfulSnapshots'] += 1
            if union['successfulSnapshots']:
                union['state'] = 'observed'
        except OSError:
            union['state'] = 'unreadable'
        except (KeyError, TypeError, ValueError, OverflowError, UnicodeError):
            union['state'] = 'invalid'
    errors = {'state': 'missing', 'unionFailuresObserved': None}
    if error_path.exists():
        try:
            lines = error_path.read_text(encoding='utf-8-sig').splitlines()
            errors = {'state': 'observed', 'unionFailuresObserved': any('union exit ' in line for line in lines),
                      'otherErrorsPresent': any('union exit ' not in line for line in lines if line.strip())}
        except (OSError, UnicodeError):
            errors = {'state': 'unreadable', 'unionFailuresObserved': None}
    return {'sampling': {'state': sample_state, 'samples': len(sample_rows),
                         'invalidSamples': len(invalid_samples),
                         'unlocatedInvalidSamples': sum(item['time'] is None for item in invalid_samples)},
            'union': union, 'errors': errors, 'coverage': 'unproven'}


def latency_qualification(latency):
    """A negative latency signals clock skew, so it cannot pass the pilot gate."""
    p99, negative, count = latency.get('p99'), latency.get('negativeSamples'), latency.get('count')
    if (type(p99) not in (int, float) or not math.isfinite(p99)
            or type(count) is not int or count < 1 or type(negative) is not int or not 0 <= negative <= count):
        return None, ['latency-evidence-unavailable']
    if negative > 0 or p99 < 0:
        return None, ['negative-latency-clock-skew']
    return p99 <= PILOT_WEC_P99_LIMIT, []


def counter_rate(rows, section, key):
    """A rate is unknown across restarts, missing identities, resets or bad times."""
    if len(rows) < 2:
        return None
    elapsed, total = 0, 0
    for a, b in zip(rows, rows[1:]):
        first, second = a.get(section), b.get(section)
        if not isinstance(first, dict) or not isinstance(second, dict):
            return None
        pid, started = first.get('pid'), first.get('startedAt')
        if type(pid) is not int or pid <= 0 or not isinstance(started, str):
            return None
        if pid != second.get('pid') or started != second.get('startedAt'):
            return None
        try:
            start_time = qf.stamp(started)
            left_time, right_time = qf.stamp(a['at']), qf.stamp(b['at'])
        except (KeyError, TypeError, ValueError, OverflowError):
            return None
        left, right = first.get(key), second.get(key)
        if (type(left) not in (int, float) or type(right) not in (int, float)
                or not math.isfinite(left) or not math.isfinite(right)
                or left < 0 or right < left or right_time <= left_time or start_time > left_time):
            return None
        elapsed += right_time - left_time
        total += right - left
    return round(total / elapsed * 3600, 1)


def forward_status(row):
    matching = [item for item in row.get('windowsEventLog', [])
                if isinstance(item, dict) and str(item.get('channel', '')).casefold() == 'forwardedevents']
    return matching[0] if len(matching) == 1 else {}


def record_position(value):
    """A native receiving-channel position is a nonnegative Int64, not a boolean."""
    return value if type(value) is int and 0 <= value <= 9223372036854775807 else None


def lag_eligibility(rows, invalid_samples):
    """Do not infer lag after a gap, reset, restart or unobserved discontinuity."""
    unlocated = any(item['time'] is None for item in invalid_samples)
    first_invalid = min((item['time'] for item in invalid_samples if item['time'] is not None), default=None)
    tainted, previous, result = unlocated, None, {}
    saw_nonempty_channel = False
    previous_newest, previous_bookmark = None, None
    for row in rows:
        time = qf.stamp(row['at'])
        identity = (row['process']['pid'], row['process']['startedAt'])
        status = forward_status(row)
        forwarded = row.get('forwardedEvents') or {}
        records = forwarded.get('records')
        if type(records) is int and records > 0:
            saw_nonempty_channel = True
        elif type(records) is int and records == 0 and saw_nonempty_channel:
            # A clear can be followed by regrowth past the prior record IDs without
            # incrementing the sampled source counters; continuity is still unknown.
            tainted = True
        newest = (record_position(forwarded.get('newestRecordId'))
                  if forwarded.get('newestRecordIdBasis') == 'native-receiving-bookmark-v1'
                  and forwarded.get('newestRecordIdState') == 'observed' else None)
        bookmark = record_position(status.get('bookmarkRecordId'))
        if (first_invalid is not None and first_invalid <= time
                or previous is not None and (identity != previous[0] or time <= previous[1])
                or type(status.get('gaps')) is not int or status['gaps'] != 0
                or type(status.get('resets')) is not int or status['resets'] != 0
                or newest is not None and previous_newest is not None and newest < previous_newest
                or bookmark is not None and previous_bookmark is not None and bookmark < previous_bookmark
                or newest is not None and bookmark is not None and newest < bookmark):
            tainted = True
        result[id(row)] = not tainted
        previous = identity, time
        if newest is not None:
            previous_newest = newest
        if bookmark is not None:
            previous_bookmark = bookmark
    return result


def resources(rows, start, end, upgrade_at=None, invalid_samples=None, missing_samples=False):
    """CPU per hour (process, user, kernel, Event Log service), reader lag and source counters."""
    invalid_samples = invalid_samples or []
    rows = [r for r in rows if start - 120 <= qf.stamp(r['at']) <= end + 120]
    eligible = lag_eligibility(rows, invalid_samples)
    unlocated_invalid = sum(item['time'] is None for item in invalid_samples)
    hours = []
    t = start
    while t < end:
        u = min(end, t + 3600)
        inside = [r for r in rows if t <= qf.stamp(r['at']) < u]
        windows = [forward_status(r) for r in inside]
        invalid_hour = sum(item['time'] is not None and t <= item['time'] < u for item in invalid_samples)
        coverage_unknown = bool(missing_samples or invalid_hour or unlocated_invalid)
        # RecordCount is a count, not the newest RecordId; the channel can wrap.
        # A reset, a missing bookmark, or a missing newest ID makes lag unknown.
        lags = []
        for r, w in zip(inside, windows):
            forwarded = r.get('forwardedEvents') or {}
            newest = record_position(forwarded.get('newestRecordId'))
            bookmark = record_position(w.get('bookmarkRecordId'))
            if (not coverage_unknown and eligible[id(r)]
                    and forwarded.get('newestRecordIdBasis') == 'native-receiving-bookmark-v1'
                    and forwarded.get('newestRecordIdState') == 'observed'
                    and newest is not None and bookmark is not None
                    and bookmark > 0 and newest >= bookmark):
                lags.append(newest - bookmark)
        cpu = counter_rate(inside, 'process', 'cpuSeconds')
        user = counter_rate(inside, 'process', 'userSeconds')
        kernel = counter_rate(inside, 'process', 'kernelSeconds')
        service = counter_rate(inside, 'eventLogService', 'cpuSeconds')
        queue_max = max((r['queue']['delivered'] for r in inside), default=None)
        channel_count = inside[-1]['forwardedEvents']['records'] if inside else None
        hours.append({
            'from': iso(t), 'to': iso(u), 'samples': len(inside),
            'coverage': 'unknown' if coverage_unknown else ('observed' if inside else 'empty'),
            'invalidSamples': invalid_hour, 'unlocatedInvalidSamples': unlocated_invalid,
            'cpuSecondsPerHour': None if coverage_unknown else cpu,
            'userSecondsPerHour': None if coverage_unknown else user,
            'kernelSecondsPerHour': None if coverage_unknown else kernel,
            'eventLogServiceCpuSecondsPerHour': None if coverage_unknown else service,
            'observedCpuSecondsPerHour': cpu,
            'observedUserSecondsPerHour': user,
            'observedKernelSecondsPerHour': kernel,
            'observedEventLogServiceCpuSecondsPerHour': service,
            'readerLagRecords': {'max': max(lags) if lags else None, 'p50': sorted(lags)[len(lags) // 2] if lags else None,
                                 'knownSamples': len(lags), 'unknownSamples': len(inside) - len(lags),
                                 'interpretation': 'observed receiving-channel ID distance; assumes no unobserved clear or reset; not unread count or continuity proof'},
            'queueRowsMax': None if coverage_unknown else queue_max,
            'forwardedEventsRecords': None if coverage_unknown else channel_count,
            'observedQueueRowsMax': queue_max, 'observedForwardedEventsRecords': channel_count,
            'states': sorted({w.get('state') for w in windows if w.get('state')}),
            'pids': sorted({r['process']['pid'] for r in inside}),
        })
        t = u
    last = forward_status(rows[-1]) if rows else {}
    return {'hours': hours, 'finalSourceCounters': {k: last.get(k) for k in (
        'eventsRead', 'queued', 'duplicates', 'retries', 'submitFailures', 'readErrors', 'gaps', 'resets', 'cursorConflicts')},
        'upgradeAt': iso(upgrade_at) if upgrade_at else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    parser.add_argument('--lab-dir', type=Path, required=True)
    parser.add_argument('--start', type=int, required=True)
    parser.add_argument('--end', type=int, required=True)
    parser.add_argument('--collector', action='append', required=True, help='HOST=CollectorId')
    parser.add_argument('--upgrade-at', type=int, help='epoch the new build was installed on Wec')
    parser.add_argument('--window', action='append', default=[], help='NAME=FROM:TO (epochs) for extra latency quantiles')
    parser.add_argument('--out', type=Path, required=True)
    arguments = sys.argv[1:]
    if '-h' in arguments or '--help' in arguments:
        parser.parse_args(arguments)  # Help does not run a reconciliation or modify reports.
    output, output_count = path_argument(arguments, '--out')
    lab_input, lab_count = path_argument(arguments, '--lab-dir')
    if output_count > 1 or lab_count > 1:
        parser.error('Specify --out and --lab-dir exactly once')
    # Only invalidate an explicit report after proving it cannot replace lab input.
    # A failed or ambiguous invocation must still be detected by its nonzero exit status.
    if output is not None and lab_input is not None:
        try:
            verify_disjoint_report(lab_input, output)
        except ValueError:
            parser.error('Report path is not safely disjoint from the lab input tree')
        write_report(output, {'status': 'invalid', 'reason': 'reconciliation-not-completed'})
    args = parser.parse_args(arguments)
    if output is None or lab_input is None or args.out != output or args.lab_dir != lab_input:
        parser.error('Specify one unambiguous --out and --lab-dir path')
    lab = args.lab_dir
    windows_named = [(w.split('=', 1)[0], *map(int, w.split('=', 1)[1].split(':'))) for w in args.window]
    expected, windows = native(lab, args.start, args.end)
    native_complete = native_window_complete(windows, args.start, args.end)
    verifier = Verifier(lab / 'azure')
    result = {'status': 'complete', 'run': lab.name, 'start': iso(args.start), 'end': iso(args.end),
              'native': {'distinct': len(expected), 'sha256': digest(expected), 'windows': windows,
                         'completeWindow': native_complete},
              'pilotWecP99LimitSeconds': PILOT_WEC_P99_LIMIT, 'collectors': {}}
    for item in args.collector:
        host, collector = item.split('=', 1)
        queue = accepted(lab, host)
        rows, hours, latency, hashes = sentinel(verifier, collector, args.start, args.end)
        destination = set(rows)
        comparison = reconcile_identities(expected, queue, destination, args.start, args.end)
        in_window_queue = comparison['accepted']
        duplicate_rows = sum(r['Copies'] - 1 for r in rows.values())
        try:
            sample_rows, invalid_samples = samples(lab, host)
            sample_state = ('partial' if sample_rows else 'invalid') if invalid_samples else ('observed' if sample_rows else 'empty')
        except FileNotFoundError:
            sample_rows, invalid_samples, sample_state = [], [], 'missing'
        except (ValueError, UnicodeError):
            sample_rows, invalid_samples, sample_state = [], [{'line': None, 'time': None, 'reason': 'unreadable-samples'}], 'invalid'
        coverage = capture_evidence(lab, host, sample_state, sample_rows, invalid_samples)
        problems = ['native-channel-continuity-unproven', 'accepted-capture-coverage-unproven']
        if not native_complete:
            problems.append('native-window-incomplete')
        if not expected:
            problems.append('native-empty')
        if comparison['indeterminate']:
            problems.append('accepted-window-indeterminate')
        if not (expected == in_window_queue == destination):
            problems.append('observed-identity-mismatch')
        if duplicate_rows:
            problems.append('sentinel-duplicate-rows')
        if coverage['union']['state'] != 'observed':
            problems.append('union-snapshots-' + coverage['union']['state'])
        if coverage['errors']['state'] != 'observed':
            problems.append('error-log-' + coverage['errors']['state'])
        if coverage['errors']['unionFailuresObserved']:
            problems.append('union-failures-observed')
        if coverage['errors'].get('otherErrorsPresent'):
            problems.append('other-agent-errors-observed')
        if sample_state != 'observed':
            problems.append('samples-' + sample_state)
        sample_latency_pass, sample_latency_problems = latency_qualification(latency)
        latency_problems = ['workload-coverage-unproven', 'destination-completeness-unproven'] + problems + sample_latency_problems
        if expected - destination:
            latency_problems.append('expected-events-missing-from-destination')
        result['collectors'][host] = {
            'collectorId': collector,
            'accepted': {'distinct': len(in_window_queue), 'sha256': digest(in_window_queue),
                         'indeterminateWindow': len(comparison['indeterminate']),
                         'outsideWindow': len(comparison['outside'])},
            'sentinel': {'distinct': len(destination), 'rows': sum(r['Copies'] for r in rows.values()),
                         'duplicateRows': duplicate_rows, 'sha256': digest(destination),
                         'queryHashes': hashes},
            'availableObservedSetsEqual': expected == in_window_queue == destination,
            'observationScope': 'Equality of available observations only; source and capture completeness are unproven',
            'captureEvidence': coverage,
            'exact': False,  # No independently verified channel continuity or complete union capture yet.
            'exactQualificationProblems': problems,
            'missingFromAccepted': len(expected - in_window_queue), 'extraInAccepted': len(in_window_queue - expected),
            'missingFromSentinel': len(expected - destination), 'extraInSentinel': len(destination - expected),
            'latencySeconds': latency,
            'observedSampleP99WithinLimit': sample_latency_pass,
            'latencyPassesPilotLimit': None,  # Complete workload and delivery coverage are unproven.
            'latencyQualificationProblems': latency_problems,
            'latencyByWindow': hours,
            'latencyByNamedWindow': {name: quantiles([qf.stamp(r['FirstIngested']) - qf.stamp(r['Generated']) for r in rows.values()
                                                      if a <= qf.stamp(r['Generated']) < b])
                                     for name, a, b in windows_named},
            'resources': resources(sample_rows, args.start, args.end, args.upgrade_at if host == 'Wec' else None,
                                   invalid_samples, sample_state == 'missing'),
        }
    write_report(args.out, result)
    print(json.dumps({h: {k: c[k] for k in ('availableObservedSetsEqual', 'exact', 'exactQualificationProblems',
                                             'latencySeconds', 'observedSampleP99WithinLimit',
                                             'latencyPassesPilotLimit', 'latencyQualificationProblems', 'latencyByNamedWindow')}
                      for h, c in result['collectors'].items()}, indent=1))


if __name__ == '__main__':
    main()
