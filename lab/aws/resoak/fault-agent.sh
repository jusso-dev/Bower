#!/bin/bash
# Re-soak fault and canary agent for the Linux hosts (the firewall collector "Linux" and the
# rsyslog/RELP "Sender"). A systemd timer runs one tick a minute, also after a reboot, so the
# pre-registered fault schedule (preregistration.json) and the canaries run on the hosts with no
# operator session. Every fault writes a metadata-only record before and after it acts; records
# go to the run bucket and to the RunId-owned identity bucket. Public parameters only:
#   RESOAK_ACTION=install|status|tick, RESOAK_HOST=Linux|Sender, RESOAK_START (epoch),
#   RESOAK_PLAN_SHA256; Linux also RESOAK_SERVER_NEXT_SHA256, RESOAK_SERVER_KEY_NEXT_SHA256,
#   RESOAK_INGEST_NEXT_SHA256 (public digests of the pre-staged rotation material).
set -euo pipefail
umask 077
: "${BOWER_LAB_BUCKET:?}" "${BOWER_LAB_RUN:?}" "${BOWER_EVIDENCE_BUCKET:?}"
[[ "$BOWER_LAB_RUN" =~ ^bower-resoak-[0-9]{8}-[0-9]{6}$ && "$BOWER_EVIDENCE_BUCKET" == "$BOWER_LAB_RUN-ids" ]]
[ "$(id -u)" = 0 ]
dir=/var/lib/bower-lab/resoak
mkdir -p "$dir"
action=${RESOAK_ACTION:-status}
if [ "$action" = install ]; then
  : "${RESOAK_HOST:?}" "${RESOAK_START:?}" "${RESOAK_PLAN_SHA256:?}"
  [[ "$RESOAK_HOST" =~ ^(Linux|Sender)$ && "$RESOAK_START" =~ ^[0-9]+$ && "$RESOAK_PLAN_SHA256" =~ ^[0-9a-f]{64}$ ]]
  [ ! -e "$dir/agent.env" ] || { echo '{"error":"agent already installed"}'; exit 1; }
  install -d -m 0700 "$dir/stage"
  aws s3 cp --only-show-errors "s3://$BOWER_LAB_BUCKET/artifacts/qualification/$BOWER_LAB_RUN/sender/resoak-plan.json" "$dir/plan.json"
  echo "$RESOAK_PLAN_SHA256  $dir/plan.json" | sha256sum --check --strict --quiet
  if [ "$RESOAK_HOST" = Linux ]; then
    for pair in "server-next.pem:$RESOAK_SERVER_NEXT_SHA256" "server-next-key.pem:$RESOAK_SERVER_KEY_NEXT_SHA256" \
                "ingest-next.pem:$RESOAK_INGEST_NEXT_SHA256"; do
      name=${pair%%:*}; sum=${pair#*:}
      [[ "$sum" =~ ^[0-9a-f]{64}$ ]]
      aws s3 cp --only-show-errors "s3://$BOWER_LAB_BUCKET/artifacts/resoak/linux/$name" "$dir/stage/$name"
      echo "$sum  $dir/stage/$name" | sha256sum --check --strict --quiet
    done
    # The rotated server certificate must chain to the CA the sender trusts and match its key.
    openssl verify -CAfile /etc/bower/syslog/ca.pem "$dir/stage/server-next.pem" >/dev/null
    [ "$(openssl x509 -in "$dir/stage/server-next.pem" -pubkey -noout)" = "$(openssl pkey -in "$dir/stage/server-next-key.pem" -pubout)" ]
  fi
  sed -n '/^# WORKER$/,/^WORKER$/p' "$0" | sed '1d;$d' > /opt/bower-lab/resoak-agent.py
  printf 'BOWER_LAB_BUCKET=%s\nBOWER_LAB_RUN=%s\nBOWER_EVIDENCE_BUCKET=%s\nRESOAK_HOST=%s\nRESOAK_START=%s\nAWS_DEFAULT_REGION=ap-southeast-2\n' \
    "$BOWER_LAB_BUCKET" "$BOWER_LAB_RUN" "$BOWER_EVIDENCE_BUCKET" "$RESOAK_HOST" "$RESOAK_START" > "$dir/agent.env"
  cat > /etc/systemd/system/bower-resoak-agent.service <<'UNIT'
[Unit]
Description=Bower re-soak fault and canary agent (lab)
After=network-online.target
[Service]
Type=oneshot
EnvironmentFile=/var/lib/bower-lab/resoak/agent.env
ExecStart=/usr/bin/python3 /opt/bower-lab/resoak-agent.py tick
TimeoutStartSec=300
UNIT
  cat > /etc/systemd/system/bower-resoak-agent.timer <<'UNIT'
[Unit]
Description=Bower re-soak agent every minute (lab)
[Timer]
OnCalendar=*:*:00
AccuracySec=1s
Persistent=false
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  set -a; . "$dir/agent.env"; set +a
  python3 /opt/bower-lab/resoak-agent.py setup
  systemctl enable --now bower-resoak-agent.timer
  echo "{\"installed\":true,\"host\":\"$RESOAK_HOST\",\"agentSha256\":\"$(sha256sum /opt/bower-lab/resoak-agent.py | cut -c1-64)\",\"timer\":\"$(systemctl is-active bower-resoak-agent.timer)\"}"
  exit 0
fi
set -a; . "$dir/agent.env"; set +a
exec python3 /opt/bower-lab/resoak-agent.py "$action"
# The worker below is data for bash (a quoted here-document), extracted by the sed above.
: <<'WORKER'
# WORKER
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

DIR = Path('/var/lib/bower-lab/resoak')
RUN, BUCKET, EVIDENCE = os.environ['BOWER_LAB_RUN'], os.environ['BOWER_LAB_BUCKET'], os.environ['BOWER_EVIDENCE_BUCKET']
HOST, START = os.environ['RESOAK_HOST'], int(os.environ['RESOAK_START'])
PLAN = json.loads((DIR / 'plan.json').read_text())
SECONDS = PLAN['profile']['soakSeconds']
LATE_LIMIT = 600            # a fault more than 10 minutes late is recorded as missed, never run late
CANARY_TABLE = 'bower_resoak_canary'
OUTAGE_TABLE = 'bower_resoak_outage'
NETNS = 'bower-client'


def now():
    return dt.datetime.now(dt.timezone.utc)


def run(*args, timeout=120, check=True):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def collector():
    """Process identity of bower.service (Linux collector only)."""
    show = run('systemctl', 'show', 'bower.service', '--property=MainPID,NRestarts,ActiveState,ActiveEnterTimestamp', check=False).stdout
    values = dict(line.split('=', 1) for line in show.splitlines() if '=' in line)
    return {'pid': int(values.get('MainPID') or 0), 'nRestarts': int(values.get('NRestarts') or 0),
            'state': values.get('ActiveState'), 'activeSince': values.get('ActiveEnterTimestamp')}


def append(name, record):
    with (DIR / name).open('a') as stream:
        stream.write(json.dumps(record, separators=(',', ':')) + '\n')


def upload(names):
    prefix = ('sender/' if HOST == 'Sender' else 'hosts/linux/') + 'resoak/'
    stack = 'results/sender/resoak/' if HOST == 'Sender' else 'results/resoak/' + RUN + '/linux/'
    for name in names:
        path = DIR / name
        if path.exists():
            for target in ('s3://' + EVIDENCE + '/' + prefix + name, 's3://' + BUCKET + '/' + stack + name):
                # A failed upload never stops a tick (faults and canaries come first); the next
                # hourly or final upload sends the whole file again.
                result = run('aws', 's3', 'cp', '--only-show-errors', '--sse', 'AES256', str(path), target, timeout=120, check=False)
                if result.returncode:
                    append('upload-errors.jsonl', {'at': now().isoformat(), 'name': name, 'target': target.split('/')[2], 'code': result.returncode})


def nft_counter(table):
    listing = json.loads(run('nft', '-j', 'list', 'table', 'inet', table).stdout)
    return sum(e['counter']['packets'] for item in listing['nftables'] if 'rule' in item
               for e in item['rule']['expr'] if 'counter' in e)


def setup():
    """Install-time preparation: the sender's canary rule (its own table and counter)."""
    if HOST == 'Sender' and run('nft', 'list', 'table', 'inet', CANARY_TABLE, check=False).returncode:
        rules = ('table inet %s {\n chain input {\n  type filter hook input priority 0; policy accept;\n'
                 '  iifname "bwf0" udp dport 4399 counter log prefix "BOWER_DENY A " drop\n }\n}\n') % CANARY_TABLE
        (DIR / 'canary.nft').write_text(rules)
        run('nft', '-c', '-f', str(DIR / 'canary.nft'))
        run('nft', '-f', str(DIR / 'canary.nft'))
    # The table is not persistent: re-created by the first tick after a reboot (only the
    # collector is rebooted by the schedule; the sender is not).
    print(json.dumps({'setup': HOST, 'faults': [f['id'] for f in PLAN['faults'] if HOST in f['hosts']]}))


def canary(at):
    """One canary denial per minute of the soak: a13-n4399x<20000 + minute>."""
    minute = int((at.timestamp() - START) // 60)
    if not 0 <= minute < SECONDS // 60 or (DIR / 'canary' / str(minute)).exists():
        return
    (DIR / 'canary').mkdir(exist_ok=True)
    if run('nft', 'list', 'table', 'inet', CANARY_TABLE, check=False).returncode:
        setup()
    before = nft_counter(CANARY_TABLE)
    code = ("import socket\nk=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            "k.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            "k.bind(('172.19.0.2',%d)); k.sendto(b'bower-canary',('172.19.0.1',4399)); k.close()\n") % (20000 + minute)
    result = run('ip', 'netns', 'exec', NETNS, 'python3', '-c', code, check=False, timeout=30)
    time.sleep(0.2)
    record = {'minute': minute, 'id': 'a13-n4399x%d' % (20000 + minute), 'sentAt': now().isoformat(),
              'exitCode': result.returncode, 'counterDelta': nft_counter(CANARY_TABLE) - before}
    append('canary.jsonl', record)
    (DIR / 'canary' / str(minute)).write_text(record['sentAt'])


def outage_restore(fault):
    """Record the restoration once: by the armed timer (its own marker) or, if the block is
    still in place at the planned end, by this tick."""
    done = DIR / 'faults' / (fault['id'] + '.restored')
    if done.exists():
        return
    timer = DIR / ('outage-restored-' + fault['id'])
    if run('nft', 'list', 'table', 'inet', OUTAGE_TABLE, check=False).returncode == 0:
        packets = nft_counter(OUTAGE_TABLE)
        run('nft', 'delete', 'table', 'inet', OUTAGE_TABLE)
        record = {'restoredAt': now().isoformat(), 'by': 'tick', 'blockedPackets': packets}
    elif timer.exists():
        final = DIR / ('outage-final-' + fault['id'] + '.json')
        try:
            listing = json.loads(final.read_text())
            packets = sum(e['counter']['packets'] for item in listing['nftables'] if 'rule' in item
                          for e in item['rule']['expr'] if 'counter' in e)
        except (OSError, ValueError, KeyError):
            packets = None
        record = {'restoredAt': timer.read_text().strip(), 'by': 'timer', 'blockedPackets': packets}
    else:
        record = {'restoredAt': None, 'by': 'unknown', 'error': 'outage-table-missing-without-restore-record'}
    append('faults.jsonl', {'fault': fault['id'], 'step': 'restored', 'at': now().isoformat(), 'bootId': boot_id(), **record})
    done.write_text(now().isoformat())
    upload(['faults.jsonl'])


def act(fault, at):
    kind = fault['kind']
    detail = {}
    if kind == 'destination-outage' and HOST == 'Linux':
        uid = int(run('id', '-u', 'bower').stdout.strip())
        rules = ('table inet %s {\n chain output {\n  type filter hook output priority 0; policy accept;\n'
                 '  meta skuid %d tcp dport 443 counter drop\n }\n}\n') % (OUTAGE_TABLE, uid)
        (DIR / 'outage.nft').write_text(rules)
        run('nft', '-c', '-f', str(DIR / 'outage.nft'))
        # The independent restore is armed before the block is applied; the tick also restores.
        restore = ('/usr/sbin/nft -j list table inet {t} > {d}/outage-final-{f}.json; /usr/sbin/nft delete table inet {t} && '
                   'date -u +%Y-%m-%dT%H:%M:%SZ > {d}/outage-restored-{f}').format(t=OUTAGE_TABLE, d=DIR, f=fault['id'])
        run('systemd-run', '--quiet', '--unit=bower-resoak-restore-' + fault['id'].lower(),
            '--on-active=%d' % fault['durationSeconds'], '/bin/sh', '-c', restore)
        run('nft', '-f', str(DIR / 'outage.nft'))
        detail = {'blockedUid': uid, 'restoreArmedSeconds': fault['durationSeconds']}
    elif kind == 'sender-restart' and HOST == 'Sender':
        run('systemctl', 'restart', 'rsyslog', timeout=300)
        detail = {'rsyslog': run('systemctl', 'is-active', 'rsyslog', check=False).stdout.strip()}
    elif kind == 'log-rollover':
        before = run('journalctl', '--disk-usage', check=False).stdout.strip()
        run('journalctl', '--rotate')
        detail = {'journalBefore': before, 'journalAfter': run('journalctl', '--disk-usage', check=False).stdout.strip()}
    elif kind == 'credential-rotation-syslog-tls' and HOST == 'Linux':
        for name, target in (('server-next-key.pem', '/etc/bower/syslog/server-key.pem'), ('server-next.pem', '/etc/bower/syslog/server.pem')):
            info = os.stat(target)
            temporary = target + '.resoak-next'
            shutil.copyfile(DIR / 'stage' / name, temporary)
            os.chown(temporary, info.st_uid, info.st_gid)
            os.chmod(temporary, info.st_mode & 0o777)
            os.replace(temporary, target)   # atomic per file; the listener keeps the last good pair until both load
        detail = {'notAfter': run('openssl', 'x509', '-in', '/etc/bower/syslog/server.pem', '-noout', '-enddate').stdout.strip()}
    elif kind == 'collector-kill' and HOST == 'Linux':
        detail = {'killed': collector()}
        run('systemctl', 'kill', '--signal=SIGKILL', 'bower.service')
    elif kind == 'credential-rotation-ingestion' and HOST == 'Linux':
        target = '/etc/bower/secrets/ingest-next.pem'
        info = os.stat('/etc/bower/secrets/ingest.pem')
        shutil.copyfile(DIR / 'stage' / 'ingest-next.pem', target + '.tmp')
        os.chown(target + '.tmp', info.st_uid, info.st_gid)
        os.chmod(target + '.tmp', info.st_mode & 0o777)
        os.replace(target + '.tmp', target)
        env = Path('/etc/bower/bower.env')
        lines = env.read_text().splitlines()
        if sum(line.startswith('AZURE_CLIENT_CERTIFICATE_PATH=') for line in lines) != 1:
            raise RuntimeError('certificate-path-setting-not-unique')
        env.write_text('\n'.join('AZURE_CLIENT_CERTIFICATE_PATH=' + target if line.startswith('AZURE_CLIENT_CERTIFICATE_PATH=') else line
                                 for line in lines) + '\n')
        detail = {'before': collector()}
        run('systemctl', 'restart', 'bower.service', timeout=300)
    elif kind == 'host-reboot' and HOST == 'Linux':
        detail = {'collector': collector()}
    else:
        return None
    return detail


def tick():
    at = now()
    offset = at.timestamp() - START
    (DIR / 'faults').mkdir(exist_ok=True)
    for fault in PLAN['faults']:
        if HOST not in fault['hosts']:
            continue
        marker = DIR / 'faults' / fault['id']
        if (fault['kind'] == 'destination-outage' and marker.exists() and offset >= fault['at'] + fault['durationSeconds']
                and json.loads(marker.read_text()).get('step') in ('done', 'failed')):
            outage_restore(fault)
        if marker.exists() or offset < fault['at']:
            if marker.exists() and fault['kind'] == 'host-reboot' and not (DIR / 'faults' / (fault['id'] + '.after')).exists():
                state = json.loads(marker.read_text())
                if boot_id() != state.get('bootId'):
                    append('faults.jsonl', {'fault': fault['id'], 'step': 'after-reboot', 'at': at.isoformat(), 'bootId': boot_id(),
                                            'collector': collector() if HOST == 'Linux' else None})
                    (DIR / 'faults' / (fault['id'] + '.after')).write_text(at.isoformat())
                    upload(['faults.jsonl'])
            continue
        record = {'fault': fault['id'], 'kind': fault['kind'], 'host': HOST, 'plannedAt': START + fault['at'],
                  'startedAt': at.isoformat(), 'lateSeconds': round(offset - fault['at'], 1), 'bootId': boot_id()}
        if offset - fault['at'] > LATE_LIMIT:
            record.update(step='missed')
            append('faults.jsonl', record)
            marker.write_text(json.dumps(record))
            continue
        try:
            detail = act(fault, at)
            record.update(step='done', detail=detail, endedAt=now().isoformat())
        except Exception as error:  # metadata category only; the fault is recorded as failed
            record.update(step='failed', error=type(error).__name__ + ':' + str(error)[:120])
        append('faults.jsonl', record)
        marker.write_text(json.dumps(record))
        upload(['faults.jsonl'])
        if fault['kind'] == 'host-reboot' and record['step'] == 'done':
            run('systemctl', 'reboot', check=False)
            return
    if HOST == 'Sender':
        canary(at)
    if at.minute == 0 or offset >= SECONDS + 1800 and not (DIR / 'published').exists():
        upload(['faults.jsonl', 'canary.jsonl'])
        if offset >= SECONDS + 1800 and not (DIR / 'published').exists():
            if HOST == 'Sender':
                append('canary-counter.jsonl', {'at': now().isoformat(), 'packets': nft_counter(CANARY_TABLE)})
                upload(['canary-counter.jsonl'])
            (DIR / 'published').write_text(now().isoformat())


def status():
    lines = (DIR / 'faults.jsonl').read_text().splitlines() if (DIR / 'faults.jsonl').exists() else []
    canaries = (DIR / 'canary.jsonl').read_text().splitlines() if (DIR / 'canary.jsonl').exists() else []
    print(json.dumps({'host': HOST, 'faultRecords': [json.loads(x) for x in lines[-6:]], 'canaries': len(canaries),
                      'lastCanary': json.loads(canaries[-1]) if canaries else None,
                      'timer': run('systemctl', 'is-active', 'bower-resoak-agent.timer', check=False).stdout.strip()}))


{'setup': setup, 'tick': tick, 'status': status}[sys.argv[1]]()
WORKER
