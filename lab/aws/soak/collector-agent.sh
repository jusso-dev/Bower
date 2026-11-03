#!/bin/bash
# Soak agent on the Linux RPM collector, run by a systemd timer so nothing depends on the
# operator session. Every 5 minutes: one metadata-only resource/status sample. At :00 and :30:
# add the queue's identities to a union database (retention purges delivered rows after 2 h).
# Hourly and at the end: upload samples, union stats and the accepted-identity list to the run
# bucket. The token is read locally and never printed. Public parameters only:
#   BOWER_SOAK_ACTION=install|update|status|tick|upload|final, BOWER_SOAK_START (epoch),
#   BOWER_SOAK_SECONDS. update replaces only the worker of an installed agent.
set -euo pipefail
umask 077
: "${BOWER_LAB_BUCKET:?}" "${BOWER_LAB_RUN:?}"
[[ "$BOWER_LAB_RUN" =~ ^bower-soak-[0-9]{8}-[0-9]{6}$ ]]
[ "$(id -u)" = 0 ]
dir=/var/lib/bower-lab/soak
mkdir -p "$dir"
action=${BOWER_SOAK_ACTION:-status}
if [ "$action" = update ]; then
  [ -e "$dir/agent.env" ]
  sed -n '/^# WORKER$/,/^WORKER$/p' "$0" | sed '1d;$d' > /opt/bower-lab/soak-agent.py
  set -a; . "$dir/agent.env"; set +a
  python3 /opt/bower-lab/soak-agent.py tick
  echo "{\"updated\":true,\"agentSha256\":\"$(sha256sum /opt/bower-lab/soak-agent.py | cut -c1-64)\"}"
  exit 0
fi
if [ "$action" = install ]; then
  : "${BOWER_SOAK_START:?}" "${BOWER_SOAK_SECONDS:?}"
  [ ! -e "$dir/agent.env" ] || { echo '{"error":"agent already installed"}'; exit 1; }
  sed -n '/^# WORKER$/,/^WORKER$/p' "$0" | sed '1d;$d' > /opt/bower-lab/soak-agent.py
  printf 'BOWER_LAB_BUCKET=%s\nBOWER_LAB_RUN=%s\nBOWER_SOAK_START=%s\nBOWER_SOAK_SECONDS=%s\nAWS_DEFAULT_REGION=ap-southeast-2\n' \
    "$BOWER_LAB_BUCKET" "$BOWER_LAB_RUN" "$BOWER_SOAK_START" "$BOWER_SOAK_SECONDS" > "$dir/agent.env"
  cat > /etc/systemd/system/bower-soak-agent.service <<'UNIT'
[Unit]
Description=Bower soak sampler and identity exporter (lab)
[Service]
Type=oneshot
EnvironmentFile=/var/lib/bower-lab/soak/agent.env
ExecStart=/usr/bin/python3 /opt/bower-lab/soak-agent.py tick
TimeoutStartSec=600
UNIT
  cat > /etc/systemd/system/bower-soak-agent.timer <<'UNIT'
[Unit]
Description=Bower soak agent every 5 minutes (lab)
[Timer]
OnCalendar=*:0/5
AccuracySec=1s
Persistent=false
[Install]
WantedBy=timers.target
UNIT
  # Monitoring deployment: the packaged-path host health check from deploy/sentinel/monitoring.
  install -d -m 0755 /opt/bower/monitoring
  aws s3 cp --only-show-errors "s3://$BOWER_LAB_BUCKET/artifacts/soak/linux/bower-healthcheck.py" /opt/bower/monitoring/bower-healthcheck.py
  aws s3 cp --only-show-errors "s3://$BOWER_LAB_BUCKET/artifacts/soak/linux/bower-healthcheck.service" /etc/systemd/system/bower-healthcheck.service
  aws s3 cp --only-show-errors "s3://$BOWER_LAB_BUCKET/artifacts/soak/linux/bower-healthcheck.timer" /etc/systemd/system/bower-healthcheck.timer
  chmod 0644 /opt/bower/monitoring/bower-healthcheck.py /etc/systemd/system/bower-healthcheck.*
  # This lab keeps the token at /etc/bower/secrets/token (setup-firewall-collector.sh).
  sed -i 's#/etc/bower/secrets/ingest-token#/etc/bower/secrets/token#' /etc/systemd/system/bower-healthcheck.service
  systemctl daemon-reload
  systemctl enable --now bower-healthcheck.timer bower-soak-agent.timer
  python3 /opt/bower-lab/soak-agent.py tick
  echo "{\"installed\":true,\"agentSha256\":\"$(sha256sum /opt/bower-lab/soak-agent.py | cut -c1-64)\",\"healthcheck\":\"$(systemctl is-active bower-healthcheck.timer)\"}"
  exit 0
fi
set -a; . "$dir/agent.env"; set +a
exec python3 /opt/bower-lab/soak-agent.py "$action"
# The worker below is data for bash (a quoted here-document), extracted by the sed above.
: <<'WORKER'
# WORKER
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request

DIR = Path('/var/lib/bower-lab/soak')
QUEUE = Path('/var/lib/bower/queue.db')
TOKEN = Path('/etc/bower/secrets/token')
RUN, BUCKET = os.environ['BOWER_LAB_RUN'], os.environ['BOWER_LAB_BUCKET']
START, SECONDS = int(os.environ['BOWER_SOAK_START']), int(os.environ['BOWER_SOAK_SECONDS'])
PREFIX = 'results/soak/' + RUN + '/linux/'
SOURCE = ('framesReceived', 'queued', 'duplicates', 'rejected', 'parserErrors', 'malformed', 'oversized', 'dropped',
          'retries', 'submitFailures', 'receiveErrors', 'tlsHandshakeFailures', 'connectionsAccepted', 'connectionsRejected',
          'activeConnections', 'relpAcknowledged', 'relpBusyCloses', 'peerResets', 'timeouts', 'framingErrors')


def now():
    return dt.datetime.now(dt.timezone.utc)


def status():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request('http://127.0.0.1:4319/v1/status',
                                     headers={'Authorization': 'Bearer ' + TOKEN.read_text().strip()})
    with opener.open(request, timeout=10) as response:
        return json.loads(response.read(2 * 1024 * 1024))


def show(prop):
    return subprocess.run(['systemctl', 'show', 'bower.service', '--property=' + prop, '--value'],
                          capture_output=True, text=True, timeout=10).stdout.strip()


def sample():
    at = now()
    row = {'at': at.isoformat(), 'offsetSeconds': round(at.timestamp() - START, 1),
           'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'error': None}
    try:
        pid = int(show('MainPID'))
        stat = Path('/proc/%d/stat' % pid).read_text()
        fields = stat[stat.rindex(')') + 2:].split()
        tick = os.sysconf('SC_CLK_TCK')
        row['process'] = {'pid': pid, 'startTicks': int(fields[19]), 'cpuSeconds': (int(fields[11]) + int(fields[12])) / tick,
                          'rssBytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE'), 'threads': int(fields[17]),
                          'fds': len(os.listdir('/proc/%d/fd' % pid)), 'nRestarts': int(show('NRestarts') or 0),
                          'activeSince': show('ActiveEnterTimestamp')}
        disk = os.statvfs(QUEUE.parent)
        row['disk'] = {'availableBytes': disk.f_bavail * disk.f_frsize, 'totalBytes': disk.f_blocks * disk.f_frsize}
        row['files'] = {name: (QUEUE.parent / name).stat().st_size for name in ('queue.db', 'queue.db-wal', 'queue.db-shm')
                        if (QUEUE.parent / name).exists()}
        s = status()
        queue = s['queue']
        oldest = queue.get('oldestUndelivered')
        queue['pending'] = queue['queued'] + queue['retrying'] + queue['uploading']
        # .NET writes seven fractional digits; Python 3.9 parses at most six.
        oldest = re.sub(r'\.(\d{6})\d+', r'.\1', oldest) if oldest else None
        queue['oldestAgeSeconds'] = (at - dt.datetime.fromisoformat(oldest)).total_seconds() if oldest else 0
        row['queue'] = queue
        row['status'] = s['status']
        row['jobs'] = {job['id']: {'lastRunAt': job['lastRunAt'], 'lastState': job['lastState']} for job in s['jobs']}
        row['delivery'] = s['deliveryActivity']
        row['syslog'] = {key: sum(item.get(key) or 0 for item in s['syslog']) for key in SOURCE}
        row['queuePages'] = s.get('queuePages')
    except Exception as error:  # metadata category only
        row['error'] = type(error).__name__
    with (DIR / 'samples.jsonl').open('a') as stream:
        stream.write(json.dumps(row, separators=(',', ':')) + '\n')
    return row


def union():
    db = sqlite3.connect('file:' + str(DIR / 'accepted.db'), uri=True)
    db.execute('CREATE TABLE IF NOT EXISTS ids (event_id TEXT PRIMARY KEY, first_seen TEXT NOT NULL, received_at TEXT)')
    db.execute("ATTACH DATABASE ? AS q", ('file:' + str(QUEUE) + '?mode=ro',))
    before = db.execute('SELECT count(*) FROM ids').fetchone()[0]
    db.execute('INSERT OR IGNORE INTO ids SELECT event_id, ?, received_at FROM q.queue_events_v5', (now().isoformat(),))
    db.commit()
    after = db.execute('SELECT count(*) FROM ids').fetchone()[0]
    rows = db.execute('SELECT count(*) FROM q.queue_events_v5').fetchone()[0]
    db.close()
    record = {'at': now().isoformat(), 'inQueue': rows, 'unionBefore': before, 'unionAfter': after, 'added': after - before}
    with (DIR / 'union.jsonl').open('a') as stream:
        stream.write(json.dumps(record) + '\n')
    return record


def upload(names=('samples.jsonl', 'union.jsonl', 'accepted.tsv.gz')):
    if 'accepted.tsv.gz' in names:
        db = sqlite3.connect('file:' + str(DIR / 'accepted.db') + '?mode=ro', uri=True)
        ids = [row[0] + '\t' + (row[1] or '') for row in db.execute('SELECT event_id, received_at FROM ids ORDER BY event_id')]
        db.close()
        with gzip.open(DIR / 'accepted.tsv.gz', 'wt') as stream:
            stream.write('\n'.join(ids) + '\n')
    files = {}
    for name in names:
        path = DIR / name
        if not path.exists():
            continue
        subprocess.run(['aws', 's3', 'cp', '--only-show-errors', '--sse', 'AES256', str(path),
                        's3://' + BUCKET + '/' + PREFIX + name], check=True, timeout=300)
        files[name] = {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    return files


def main(action):
    DIR.mkdir(parents=True, exist_ok=True)
    if action == 'tick':
        if (DIR / 'final.json').exists():
            return
        at = now()
        sample()
        if at.minute % 30 < 5 or not (DIR / 'accepted.db').exists():
            union()
        if at.minute < 5:
            upload()
        if at.timestamp() >= START + SECONDS + 1800:
            main('final')
    elif action == 'final':
        record = {'finalAt': now().isoformat(), 'sample': sample(), 'union': union(), 'runId': RUN}
        # Publish the data first. final.json stops further ticks, so it is written only after
        # the data uploads succeed; a failed upload leaves the tick retry path active.
        record['uploaded'] = upload()
        (DIR / 'final.json').write_text(json.dumps(record))
        record['uploaded'].update(upload(names=('final.json',)))
        subprocess.run(['systemctl', 'disable', '--now', 'bower-soak-agent.timer'], timeout=30)
        print(json.dumps(record))
    elif action == 'upload':
        print(json.dumps({'union': union(), 'uploaded': upload()}))
    elif action == 'status':
        lines = (DIR / 'samples.jsonl').read_text().splitlines()
        print(json.dumps({'samples': len(lines), 'last': json.loads(lines[-1]) if lines else None,
                          'union': (DIR / 'union.jsonl').read_text().splitlines()[-1:],
                          'final': (DIR / 'final.json').exists()}))


main(sys.argv[1])
WORKER
