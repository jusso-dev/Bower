#!/usr/bin/env bash
# Only synthetic identity/timestamp metadata leaves the collector. No payloads.
set -euo pipefail
umask 077
python3 - <<'PY'
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import uuid

MAX_ROWS = 200000

def stamp(value):
    # .NET round-trip timestamps have seven fractional digits; Python 3.9's
    # fromisoformat accepts only three or six. Validate the exact offset form,
    # then truncate sub-microsecond precision consistently with source IDs.
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})', value):
        raise ValueError('Explicit ISO offset timestamp required')
    normalized = re.sub(r'\.(\d{1,7})(?=Z|[+-])',
                        lambda match: '.' + (match.group(1) + '000000')[:6], value)
    parsed = dt.datetime.fromisoformat(normalized.replace('Z', '+00:00'))
    return parsed.timestamp()


def export(database, run, scenario, plan_hash, blocks, start, end, pack, helper):
    expected = set()
    for block in blocks.split(','):
        match = re.fullmatch(r'nft:A:(\d+):(\d+)', block)
        if not match:
            raise ValueError('Invalid block')
        first, count = map(int, match.groups())
        if not 0 < count <= MAX_ROWS or first + count > 40000 * (65536 - 4400):
            raise ValueError('Block out of bounds')
        ids = {'a13-n{}x{}'.format(4400 + n // 40000, 20000 + n % 40000) for n in range(first, first + count)}
        if expected & ids or len(expected | ids) > MAX_ROWS:
            raise ValueError('Repeated or excessive blocks')
        expected |= ids
    rows, malformed = [], 0
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=30) as connection:
        connection.execute('PRAGMA query_only=ON')
        # Metadata projection only. Fetch historical expected IDs too, so reused
        # IDs cannot let a stale queue row mask loss in this attempt.
        cursor = connection.execute('''SELECT event_id,
            json_extract(payload, '$.timeGenerated'), received_at
            FROM queue_events
            WHERE json_extract(payload, '$.collector.id') = ?
            AND json_extract(payload, '$.application.name') = 'nftables-firewall'
            AND json_extract(payload, '$.application.environment') = 'validation'
            AND json_extract(payload, '$.eventType') = 'network_connection_denied'
            LIMIT ?''', (run + '-linux', MAX_ROWS + 1))
        count = 0
        for identity, generated, received in cursor:
            count += 1
            if count > MAX_ROWS:
                raise ValueError('Queue metadata bound exceeded')
            if not isinstance(identity, str) or not re.fullmatch(r'a13-n[0-9]{4,5}x[0-9]{5}', identity):
                malformed += 1
                continue
            try:
                generated_epoch = stamp(generated)
                stamp(received)
            except (ValueError, TypeError, AttributeError):
                malformed += 1
                continue
            if identity in expected or start <= generated_epoch <= end:
                rows.append({'eventId': identity, 'generatedAt': generated, 'receivedAt': received})
    return {'schemaVersion': 1, 'runId': run, 'collectorId': run + '-linux', 'scenario': scenario,
            'planSha256': plan_hash, 'startEpoch': start, 'endEpoch': end, 'malformedRows': malformed,
            'packSha256': hashlib.sha256(pack.read_bytes()).hexdigest(),
            'helperSha256': hashlib.sha256(helper.read_bytes()).hexdigest(),
            'exportedAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'rows': rows}


def main():
    run = os.environ['BOWER_LAB_RUN']
    bucket = os.environ['BOWER_LAB_BUCKET']
    scenario = os.environ['BOWER_SCENARIO']
    plan_hash = os.environ['BOWER_PLAN_SHA256']
    start = float(os.environ['BOWER_SCOPE_START_EPOCH'])
    end = float(os.environ['BOWER_SCOPE_END_EPOCH'])
    if (not re.fullmatch(r'bower-(?:ws6|fw|soak)-\d{8}-\d{6}', run)
            or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket)
            or not re.fullmatch(r'[ab]-[a-z0-9-]+', scenario)
            or not re.fullmatch(r'[0-9a-f]{64}', plan_hash)
            or not all(math.isfinite(value) for value in (start, end)) or not 0 < end - start <= 14402
            or os.environ.get('AWS_DEFAULT_REGION') != 'ap-southeast-2'):
        raise ValueError('Invalid export scope')
    def aws(*args):
        result = subprocess.run(['aws', '--region', 'ap-southeast-2', *args], capture_output=True, timeout=120)
        if result.returncode:
            raise RuntimeError('AWS metadata operation failed')
        return result.stdout
    identity = json.loads(aws('sts', 'get-caller-identity', '--output', 'json'))
    if identity['Account'] != '959038055523':
        raise ValueError('Unexpected AWS account')
    marker = json.loads(Path('/var/lib/bower-lab/qualification-owner.json').read_text())
    if marker != {'runId': run, 'role': 'collector'}:
        raise ValueError('Collector ownership mismatch')
    report = export(Path('/var/lib/bower/queue.db'), run, scenario, plan_hash,
                    os.environ['BOWER_EXPECTED_BLOCKS'], start, end,
                    Path('/etc/bower/packs/syslog-reliability.bowerpack'), Path('/opt/bower-lab/syslog-host.py'))
    content = (json.dumps(report, sort_keys=True) + '\n').encode()
    if len(content) > 64 * 1024 * 1024:
        raise ValueError('Oversized metadata export')
    key = 'results/firewall/{}/{}/{}.json'.format(scenario, plan_hash, uuid.uuid4().hex)
    with tempfile.TemporaryDirectory(prefix='bower-queue-identities-') as directory:
        path = Path(directory) / 'identities.json'
        path.write_bytes(content)
        aws('s3', 'cp', str(path), 's3://' + bucket + '/' + key, '--sse', 'AES256', '--only-show-errors')
    print(json.dumps({'key': key, 'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content),
                      'rows': len(report['rows']), 'malformedRows': report['malformedRows'],
                      'destinationQueryVerified': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'failed', 'category': type(error).__name__}), file=sys.stderr)
        sys.exit(1)
PY
