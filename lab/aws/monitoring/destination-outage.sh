#!/usr/bin/env bash
# Disposable qualification only: block Bower UID TCP443, with independent restoration.
set -euo pipefail
umask 077
python3 - <<'PY'
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time

RESTORE = r'''import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
root = Path(sys.argv[1])
scope = json.loads((root / 'scope.json').read_text())
record = {'runId': scope['runId'], 'planSha256': scope['planSha256'], 'table': scope['table'],
          'removed': False, 'minimumDurationPassed': False,
          'restorationStartedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
          'restorationStartedMonotonic': time.monotonic()}
try:
    # Restore only this unique owned table; never flush a shared ruleset.
    listing = subprocess.run(['nft', '-j', 'list', 'table', 'inet', scope['table']], capture_output=True, timeout=30)
    if listing.returncode:
        raise RuntimeError('Owned rule absent or unreadable before restoration')
    document = json.loads(listing.stdout)
    tables = [entry['table'] for entry in document['nftables'] if 'table' in entry]
    if len(tables) != 1 or tables[0].get('comment') != scope['ownerComment']:
        raise RuntimeError('Owned table marker changed')
    removed = subprocess.run(['nft', 'delete', 'table', 'inet', scope['table']], capture_output=True, timeout=30)
    if removed.returncode:
        raise RuntimeError('Owned rule removal failed')
    record['restoredAt'] = dt.datetime.now(dt.timezone.utc).isoformat()
    record['restoredMonotonic'] = time.monotonic()
    record['removed'] = True
    applied = json.loads((root / 'applied.json').read_text())
    record['bootUnchanged'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip() == applied['bootId']
    record['blockedSecondsLowerBound'] = record['restorationStartedMonotonic'] - applied['appliedMonotonic']
    record['minimumDurationPassed'] = record['bootUnchanged'] and record['blockedSecondsLowerBound'] >= 3600
except Exception as error:
    # Removal can succeed even when the timing evidence is missing or unreadable.
    # Preserve that fact, but never mark the duration qualified without evidence.
    record['category'] = type(error).__name__
(root / 'restored.json').write_text(json.dumps(record) + '\n')
# Upload bounded metadata only; local evidence remains if AWS is unavailable.
key = scope['resultPrefix'] + '/restored.json'
uploaded = subprocess.run(['aws', '--region', 'ap-southeast-2', 's3', 'cp', str(root / 'restored.json'),
                          's3://' + scope['bucket'] + '/' + key, '--sse', 'AES256', '--only-show-errors'],
                         capture_output=True, timeout=120)
print(json.dumps({'removed': record['removed'], 'uploaded': uploaded.returncode == 0, 'key': key}))
sys.exit(0 if record['removed'] and record['minimumDurationPassed'] else 1)
'''


def scope_from_environment(environment, now):
    run, plan = environment['BOWER_LAB_RUN'], environment['BOWER_PLAN_SHA256']
    bucket = environment['BOWER_LAB_BUCKET']
    start = float(environment['BOWER_GENERATION_START_EPOCH'])
    if (not re.fullmatch(r'bower-ws6-\d{8}-\d{6}', run) or not re.fullmatch(r'[0-9a-f]{64}', plan)
            or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket)
            or environment.get('AWS_DEFAULT_REGION') != 'ap-southeast-2'
            or not math.isfinite(start) or not 30 <= start - now <= 900):
        raise ValueError('Invalid owned outage scope or generation start')
    table = 'bower_outage_' + plan[:16]
    return {'runId': run, 'planSha256': plan, 'bucket': bucket, 'table': table,
            'ownerComment': run + ':' + plan, 'generationStartEpoch': start,
            'restoreNotBeforeEpoch': start + 3605,
            'resultPrefix': 'results/firewall/a-destination-outage/' + plan + '/fault'}


def rules_for(scope, uid):
    if type(uid) is not int or uid <= 0:
        raise ValueError('Bower must have a non-root service UID')
    return '''table inet {table} {{
 comment "{owner}"
 chain output {{
  type filter hook output priority -10; policy accept;
  meta skuid {uid} tcp dport 443 drop
 }}
}}
'''.format(table=scope['table'], owner=scope['ownerComment'], uid=uid)


def main():
    scope = scope_from_environment(os.environ, time.time())
    def command(*args, input=None, check=True):
        result = subprocess.run(list(args), input=input, capture_output=True, text=True, timeout=120)
        if check and result.returncode:
            raise RuntimeError('Outage operation failed')
        return result
    identity = json.loads(command('aws', '--region', 'ap-southeast-2', 'sts', 'get-caller-identity', '--output', 'json').stdout)
    if identity['Account'] != '959038055523':
        raise ValueError('Unexpected AWS account')
    marker = json.loads(Path('/var/lib/bower-lab/qualification-owner.json').read_text())
    if marker != {'runId': scope['runId'], 'role': 'collector'}:
        raise ValueError('Collector ownership mismatch')
    if command('systemctl', 'show', 'bower.service', '--property=User', '--value').stdout.strip() != 'bower':
        raise ValueError('Collector service does not run as bower')
    uid = pwd.getpwnam('bower').pw_uid
    rules = rules_for(scope, uid)
    existing = json.loads(command('nft', '-j', 'list', 'tables').stdout)
    if any(entry.get('table', {}).get('name', '').startswith('bower_outage_') for entry in existing['nftables']):
        raise ValueError('An outage table already exists; preserve and resolve that attempt first')
    # Unique immutable local directory prevents overwriting another timer's files.
    root = Path('/var/lib/bower-lab') / scope['table']
    root.mkdir(mode=0o700)
    scope['serviceUid'] = uid
    scope['rulesSha256'] = hashlib.sha256(rules.encode()).hexdigest()
    scope['unit'] = scope['table'].replace('_', '-')
    (root / 'scope.json').write_text(json.dumps(scope) + '\n')
    (root / 'restore.py').write_text(RESTORE)
    (root / 'rules.nft').write_text(rules)
    command('nft', '--check', '-f', str(root / 'rules.nft'))
    delay = math.ceil(scope['restoreNotBeforeEpoch'] - time.time())
    if not 3600 < delay <= 4510:
        raise ValueError('Guard scheduling window expired')
    # Arm first. Restoration remains independent of this SSM process/session.
    command('systemd-run', '--unit=' + scope['unit'], '--on-active=' + str(delay) + 's',
            '--timer-property=AccuracySec=1s', '--property=Type=oneshot',
            '/usr/bin/python3', str(root / 'restore.py'), str(root))
    if command('systemctl', 'is-active', scope['unit'] + '.timer').stdout.strip() != 'active':
        raise RuntimeError('Restoration guard is not active')
    active = False
    try:
        command('nft', '-f', str(root / 'rules.nft'))
        active = True
        applied = {'runId': scope['runId'], 'planSha256': scope['planSha256'], 'table': scope['table'],
                   'appliedAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'appliedMonotonic': time.monotonic(),
                   'rulesSha256': scope['rulesSha256'], 'serviceUid': uid, 'guardArmed': True,
                   'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                   'guardUnit': scope['unit'], 'restoreNotBeforeEpoch': scope['restoreNotBeforeEpoch'],
                   'scope': 'Bower service UID outbound TCP443; IPv4 and IPv6; ingestion and token refresh',
                   'destinationOutageQualified': False}
        if time.time() >= scope['generationStartEpoch']:
            raise RuntimeError('Rule installation missed generation start')
        (root / 'applied.json').write_text(json.dumps(applied) + '\n')
        key = scope['resultPrefix'] + '/applied.json'
        command('aws', '--region', 'ap-southeast-2', 's3', 'cp', str(root / 'applied.json'),
                's3://' + scope['bucket'] + '/' + key, '--sse', 'AES256', '--only-show-errors')
        print(json.dumps({**applied, 'key': key, 'localEvidenceDirectory': str(root)}))
    except Exception:
        if active:
            # Failure before handoff must restore immediately; this is a failed test.
            command('nft', 'delete', 'table', 'inet', scope['table'])
        command('systemctl', 'stop', scope['unit'] + '.timer', check=False)
        raise


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'failed', 'category': type(error).__name__}), file=sys.stderr)
        sys.exit(1)
PY
