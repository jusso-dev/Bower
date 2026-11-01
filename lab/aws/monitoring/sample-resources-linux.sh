#!/bin/bash
# Only public scope parameters cross SSM. The background worker reads its token locally.
set -euo pipefail
umask 077
SAMPLER_SOURCE_PATH="$0" python3 - <<'PY'
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

CAP = 4 * 1024 * 1024
INTERVAL = 15
QUEUE = Path('/var/lib/bower/queue.db')
TOKEN = Path('/etc/bower/secrets/token')
QUEUE_FIELDS = ('queued', 'retrying', 'uploading', 'delivered', 'deadLettered', 'totalBytes', 'undeliveredBytes')
SOURCE_FIELDS = ('framesReceived', 'queued', 'duplicates', 'rejected', 'parserErrors', 'malformed', 'oversized',
                 'dropped', 'retries', 'submitFailures', 'receiveErrors', 'tlsHandshakeFailures', 'connectionsRejected')


def require(value, code):
    if not value:
        raise ValueError(code)


def boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch(r'[0-9a-f-]{36}', value), 'boot-id')
    return value


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def number(value):
    require(type(value) is int and 0 <= value <= 2 ** 63 - 1, 'counter')
    return value


def sanitized_status(status):
    queue = {key: number(status['queue'][key]) for key in QUEUE_FIELDS}
    queue['pending'] = sum(queue[key] for key in ('queued', 'retrying', 'uploading'))
    queue['count'] = queue['pending'] + queue['delivered'] + queue['deadLettered']
    sources = status['syslog']
    require(isinstance(sources, list) and 0 < len(sources) <= 32, 'sources')
    counters = {key: sum(number(source[key]) for source in sources) for key in SOURCE_FIELDS}
    return queue, counters


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def status_read():
    require(TOKEN.stat().st_size <= 4096, 'token-size')
    token = TOKEN.read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    request = urllib.request.Request('http://127.0.0.1:4319/v1/status', headers={'Authorization': 'Bearer ' + token})
    del token
    with opener.open(request, timeout=3) as response:
        body = response.read(1024 * 1024 + 1)
        require(response.status == 200 and len(body) <= 1024 * 1024, 'status-response')
    queue, counters = sanitized_status(json.loads(body))
    healthy = False
    try:
        with opener.open('http://127.0.0.1:4319/health', timeout=3) as response:
            healthy = response.status == 200
    except Exception:
        pass
    return queue, counters, healthy


def process_read():
    response = subprocess.run(['systemctl', 'show', 'bower.service', '--property=MainPID', '--value'],
                              capture_output=True, text=True, timeout=3)
    require(response.returncode == 0 and response.stdout.strip().isdigit(), 'service-pid')
    pid = int(response.stdout.strip())
    require(pid > 0, 'service-not-running')
    raw = Path('/proc/{}/stat'.format(pid)).read_text()
    values = raw[raw.rindex(')') + 2:].split()
    return {'pid': pid, 'startTicks': int(values[19]), 'cpuSeconds': (int(values[11]) + int(values[12])) / os.sysconf('SC_CLK_TCK'),
            'residentBytes': int(values[21]) * os.sysconf('SC_PAGE_SIZE')}


def sample(sequence, began, previous):
    now = time.monotonic()
    row = {'sequence': sequence, 'at': stamp(), 'elapsedSeconds': now - began, 'monotonicSeconds': now,
           'bootId': boot(), 'metricsAvailable': False, 'errorCategory': None}
    try:
        process = process_read()
        process['cpuPercentOfOneCore'] = None
        if previous and previous.get('process'):
            old = previous['process']
            gap = now - previous['monotonicSeconds']
            if (old['pid'], old['startTicks']) == (process['pid'], process['startTicks']) and gap > 0:
                process['cpuPercentOfOneCore'] = max(0, 100 * (process['cpuSeconds'] - old['cpuSeconds']) / gap)
        row['process'] = process
        volume = os.statvfs(QUEUE if QUEUE.exists() else QUEUE.parent)
        row['disk'] = {'availableBytes': volume.f_bavail * volume.f_frsize, 'totalBytes': volume.f_blocks * volume.f_frsize}
        row['dbWalBytes'] = sum(path.stat().st_size for path in (QUEUE, Path(str(QUEUE) + '-wal'), Path(str(QUEUE) + '-shm')) if path.exists())
        row['queue'], row['sourceCounters'], row['healthOk'] = status_read()
        row['metricsAvailable'] = True
    except Exception:
        row['errorCategory'] = 'sample-metadata-unavailable'
    return row


def load_rows(root):
    path = root / 'samples.jsonl'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= CAP, 'sample-file-bound')
    rows = []
    with path.open() as stream:
        for line in stream:
            require(len(line.encode()) <= 8192 and len(rows) < 481, 'sample-row-bound')
            rows.append(json.loads(line))
    return rows


def summary(scope, rows, finalized, current_boot):
    require(len(rows) <= 481 and all(row['sequence'] == index for index, row in enumerate(rows)), 'sample-sequence')
    good = [row for row in rows if row['metricsAvailable']]
    process_rows = [row for row in rows if row.get('process')]
    gaps = [rows[index]['monotonicSeconds'] - rows[index - 1]['monotonicSeconds'] for index in range(1, len(rows))]
    continuity = bool(rows) and all(row['bootId'] == scope['bootId'] for row in rows) and current_boot == scope['bootId']
    require(all(math.isfinite(gap) and gap >= 0 for gap in gaps) or not continuity, 'sample-clock')
    def maximum(path):
        values = []
        for row in rows:
            value = row
            for key in path:
                value = value.get(key) if isinstance(value, dict) else None
            if value is not None:
                values.append(value)
        return max(values) if values else None
    resets = 0
    increases = {key: 0 for key in SOURCE_FIELDS}
    for before, after in zip(good, good[1:]):
        for key in SOURCE_FIELDS:
            delta = after['sourceCounters'][key] - before['sourceCounters'][key]
            if delta < 0:
                resets += 1
            else:
                increases[key] += delta
    elapsed = rows[-1]['elapsedSeconds'] if rows else 0
    gap = max(gaps) if gaps else None
    return {'schemaVersion': 1, 'runId': scope['runId'], 'role': 'linux', 'scope': scope['scope'], 'planSha256': scope['planSha256'],
            'durationSeconds': scope['durationSeconds'], 'intervalSeconds': INTERVAL,
            'sampleCount': len(rows), 'availableSampleCount': len(good), 'failedSampleCount': len(rows) - len(good),
            'firstSampleAt': rows[0]['at'] if rows else None, 'lastSampleAt': rows[-1]['at'] if rows else None,
            'observedDurationSeconds': elapsed, 'maxSampleGapSeconds': gap, 'bootUnchanged': continuity,
            'processRestartCount': sum((a.get('process', {}).get('pid'), a.get('process', {}).get('startTicks')) !=
                                       (b.get('process', {}).get('pid'), b.get('process', {}).get('startTicks')) for a, b in zip(process_rows, process_rows[1:])),
            'sourceCounterResetCount': resets, 'sourceCounterIncreases': increases,
            'sourceCounterMaxima': {key: maximum(('sourceCounters', key)) for key in SOURCE_FIELDS},
            'peakPendingCount': maximum(('queue', 'pending')), 'peakQueueCount': maximum(('queue', 'count')),
            'peakQueueBytes': maximum(('queue', 'totalBytes')), 'peakUndeliveredBytes': maximum(('queue', 'undeliveredBytes')),
            'peakDeadLetterCount': maximum(('queue', 'deadLettered')), 'peakDbWalBytes': maximum(('dbWalBytes',)),
            'peakProcessResidentBytes': maximum(('process', 'residentBytes')), 'peakCpuPercentOfOneCore': maximum(('process', 'cpuPercentOfOneCore')),
            'minimumQueueVolumeAvailableBytes': min((row['disk']['availableBytes'] for row in rows if 'disk' in row), default=None),
            'finalized': finalized, 'samplingComplete': bool(finalized and continuity and good and len(good) == len(rows)
                and 0 <= rows[0]['elapsedSeconds'] <= INTERVAL
                and elapsed - rows[0]['elapsedSeconds'] >= scope['durationSeconds'] - INTERVAL
                and gap is not None and gap <= 2 * INTERVAL),
            'deliveryQualified': False}


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    temporary.replace(path)


def worker(root):
    os.umask(0o077)
    scope = json.loads((root / 'scope.json').read_text())
    began = time.monotonic()
    previous = None
    finished = False
    try:
        with (root / 'samples.jsonl').open('x') as stream:
            for index in range(scope['durationSeconds'] // INTERVAL + 1):
                due = began + index * INTERVAL
                time.sleep(max(0, due - time.monotonic()))
                row = sample(index, began, previous)
                encoded = json.dumps(row, separators=(',', ':')) + '\n'
                require(len(encoded.encode()) <= 8192 and stream.tell() + len(encoded.encode()) <= CAP, 'sample-cap')
                stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
                previous = row
            finished = True
    except Exception:
        pass
    rows = load_rows(root)
    write_json(root / 'summary.json', summary(scope, rows, finished, boot()))


def scope_from_environment(environment):
    run, scope, plan = environment['BOWER_LAB_RUN'], environment['BOWER_SAMPLE_SCOPE'], environment['BOWER_PLAN_SHA256']
    bucket = environment['BOWER_LAB_BUCKET']
    require(re.fullmatch(r'bower-ws6-\d{8}-\d{6}', run) and re.fullmatch(r'[a-z][a-z0-9-]{0,39}', scope)
            and re.fullmatch(r'[0-9a-f]{64}', plan) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket)
            and environment.get('AWS_DEFAULT_REGION') == 'ap-southeast-2', 'sampler-scope')
    return {'schemaVersion': 1, 'runId': run, 'scope': scope, 'planSha256': plan, 'bucket': bucket, 'role': 'linux'}


def private_path(path):
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            require(not part.is_symlink() and part.stat().st_uid == 0 and part.stat().st_mode & 0o022 == 0, 'private-path')


def read_metadata(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16384, 'metadata-bound')
    return json.loads(path.read_text())


def main():
    os.umask(0o077)
    scope = scope_from_environment(os.environ)
    root = Path('/var/lib/bower-lab/resource-samples') / scope['runId'] / (scope['scope'] + '-' + scope['planSha256'])
    private_path(root)
    action = os.environ.get('BOWER_SAMPLE_ACTION', 'start')
    if action == 'start':
        duration = int(os.environ.get('BOWER_SAMPLE_SECONDS', '4200'))
        require(60 <= duration <= 7140 and duration % INTERVAL == 0, 'sample-duration')
        require(os.geteuid() == 0 and not root.exists(), 'fresh-root-required')
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
        scope.update(durationSeconds=duration, intervalSeconds=INTERVAL, bootId=boot(), startedAt=stamp())
        source = Path(os.environ['SAMPLER_SOURCE_PATH']).read_text()
        code = source.split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        require(len(code.encode()) <= 1024 * 1024, 'worker-size')
        (root / 'worker.py').write_text(code)
        scope['workerSha256'] = digest(root / 'worker.py')
        write_json(root / 'scope.json', scope)
        unit = 'bower-sample-' + scope['scope'] + '-' + scope['planSha256'][:16]
        command = ['systemd-run', '--quiet', '--collect', '--unit=' + unit, '--property=Type=exec',
                   '--property=RuntimeMaxSec=' + str(duration + 55), '--property=TimeoutStopSec=5', '--property=UMask=0077',
                   '--property=StandardOutput=null', '--property=StandardError=null',
                   '/usr/bin/python3', str(root / 'worker.py'), 'worker', str(root)]
        result = subprocess.run(command, capture_output=True, timeout=15)
        require(result.returncode == 0, 'sampler-schedule')
        print(json.dumps({'started': True, 'unit': unit, 'scope': scope['scope'], 'planSha256': scope['planSha256'], 'hardLimitSeconds': duration + 60}))
        return
    require(action in ('status', 'export') and root.is_dir() and not root.is_symlink(), 'sampler-action')
    stored = read_metadata(root / 'scope.json')
    require(all(stored[key] == value for key, value in scope.items()), 'saved-scope')
    finalized = False
    if (root / 'summary.json').exists():
        finalized = read_metadata(root / 'summary.json').get('finalized') is True
    if action == 'export':
        if not (root / 'summary.json').exists():
            unit = 'bower-sample-' + scope['scope'] + '-' + scope['planSha256'][:16]
            active = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True, timeout=5)
            require(active.returncode in (3, 4) and active.stdout.strip() in ('inactive', 'failed', 'unknown'), 'sampler-not-stopped')
    result = summary(stored, load_rows(root), finalized, boot())
    if action == 'export':
        write_json(root / 'export-summary.json', result)
        exported = []
        for name in ('scope.json', 'samples.jsonl', 'export-summary.json'):
            path = root / name
            require(path.stat().st_size <= CAP and not path.is_symlink(), 'export-bound')
            key = 'results/resource-sampling/{}/linux/{}/{}/{}'.format(scope['runId'], scope['scope'], scope['planSha256'], name)
            response = subprocess.run(['aws', '--region', 'ap-southeast-2', 's3', 'cp', str(path), 's3://' + scope['bucket'] + '/' + key,
                                       '--sse', 'AES256', '--only-show-errors'], capture_output=True, timeout=60)
            require(response.returncode == 0, 'sample-upload')
            exported.append({'key': key, 'bytes': path.stat().st_size, 'sha256': digest(path)})
        result['exports'] = exported
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == 'worker':
            worker(Path(sys.argv[2]))
        else:
            main()
    except Exception:
        print('{"sampler":"failed","deliveryQualified":false}')
        sys.exit(1)
PY
