#!/bin/bash
# Metadata-only snapshot of a Linux collector (RPM or Docker). Secrets are compared with an on-host baseline.
set -euo pipefail
export LABEL='{{LABEL}}' QUEUE='{{QUEUE}}' TOKEN_FILE='{{TOKEN_FILE}}' B='{{Artifacts}}' R='{{REGION}}'
mkdir -p /var/lib/bower-lab/snap && chmod 700 /var/lib/bower-lab
python3 - <<'PY'
import hashlib, json, os, pathlib, sqlite3, subprocess, urllib.request, datetime as dt, stat
label, queue = os.environ['LABEL'], os.environ['QUEUE']
out = pathlib.Path('/var/lib/bower-lab/snap')
def sha(p):
    try: return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
    except OSError: return None
def run(*a):
    r = subprocess.run(a, capture_output=True, text=True); return r.stdout.strip()
def mode(p):
    try:
        s = os.stat(p); return {'owner': run('stat', '-c', '%U:%G', p), 'mode': oct(stat.S_IMODE(s.st_mode))}
    except OSError: return None
db = sqlite3.connect(f'file:{queue}?mode=ro', uri=True)
ids, states, attempts = [], [0]*5, 0
for event_id, state, tries in db.execute('select event_id,state,delivery_attempts from queue_events_v5 order by event_id'):
    ids.append((event_id, state)); states[state] += 1; attempts += tries > 1
cursors = [dict(zip(['sourceId','value','version','updatedAt'], r)) for r in db.execute('select "SourceId","Value","Version","UpdatedAt" from source_cursors')] if db.execute("select count(*) from sqlite_master where name='source_cursors'").fetchone()[0] else []
integrity = db.execute('pragma quick_check').fetchone()[0]
schema = db.execute('select max(version) from schema_history').fetchone()[0]
head = db.execute('select sequence, chain_hash from (select sequence, chain_hash from queue_ledger union all select end_sequence, chain_hash from queue_ledger_segments) order by sequence desc limit 1').fetchone()
db.close()
(out / f'{label}-queue.ids').write_text(''.join(f'{i}\t{s}\n' for i, s in ids))
secrets = {p.name: sha(p) for p in sorted(pathlib.Path('/etc/bower/secrets').glob('*'))} if pathlib.Path('/etc/bower/secrets').exists() else {}
base = pathlib.Path('/var/lib/bower-lab/secret-baseline.json')
if not base.exists():
    base.write_text(json.dumps(secrets)); base.chmod(0o600)
baseline = json.loads(base.read_text())
status = None
try:
    token = pathlib.Path(os.environ['TOKEN_FILE']).read_text().strip()
    req = urllib.request.Request('http://127.0.0.1:4319/v1/status', headers={'Authorization': 'Bearer ' + token})
    s = json.load(urllib.request.urlopen(req, timeout=10))
    status = {k: s.get(k) for k in ['status', 'packs', 'policyHash', 'queue', 'delivery', 'syslog', 'ledgerHead']}
except Exception as e:
    status = {'unavailable': type(e).__name__}
mainpid = run('systemctl', 'show', 'bower', '--property=MainPID', '--value') or '0'
result = {
    'label': label, 'host': run('hostname'), 'capturedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
    'service': {'active': run('systemctl', 'is-active', 'bower'), 'user': run('systemctl', 'show', 'bower', '--property=User', '--value'),
                'mainPid': mainpid, 'activeEnter': run('systemctl', 'show', 'bower', '--property=ActiveEnterTimestamp', '--value'),
                'nRestarts': run('systemctl', 'show', 'bower', '--property=NRestarts', '--value')},
    'package': run('rpm', '-q', 'bower-collector'), 'executableSha256': sha('/opt/bower/Bower.Collector'),
    'unitSha256': sha('/usr/lib/systemd/system/bower.service'),
    'config': {n: sha(p) for n, p in {'bower.env': '/etc/bower/bower.env', 'syslog.json': '/etc/bower/syslog.json', 'pack': '/etc/bower/packs/firewall.bowerpack',
               'trustedKey': '/etc/bower/keys/bower-signing.pub.pem', 'serverCert': '/etc/bower/tls/server.pem', 'ca': '/etc/bower/tls/ca.pem'}.items()},
    'secretsPresent': sorted(secrets), 'secretsUnchanged': all(secrets.get(k) == v for k, v in baseline.items()),
    'permissions': {p: mode(p) for p in ['/etc/bower', '/etc/bower/secrets', '/etc/bower/tls', '/etc/bower/bower.env', '/var/lib/bower', queue, '/var/spool/bower']},
    'queue': {'integrity': integrity, 'schemaVersion': schema, 'queued': states[0], 'uploading': states[1], 'retrying': states[2], 'delivered': states[3],
              'deadLettered': states[4], 'total': len(ids), 'attemptsAboveOne': attempts,
              'identitySetSha256': hashlib.sha256('\n'.join(i for i, _ in ids).encode()).hexdigest(),
              'ledgerHead': head, 'cursors': cursors,
              'files': {p.name: p.stat().st_size for p in pathlib.Path(queue).parent.glob(pathlib.Path(queue).name + '*')}},
    'status': status,
}
(out / f'{label}.json').write_text(json.dumps(result, indent=1))
q = result['queue']; sl = (status or {}).get('syslog') or [{}]
print(json.dumps({'label': label, 'svc': result['service']['active'], 'pkg': result['package'], 'q': [q['queued'], q['uploading'], q['retrying'], q['delivered'], q['deadLettered']],
                  'integrity': integrity, 'secretsUnchanged': result['secretsUnchanged'], 'frames': sl[0].get('framesReceived'), 'dups': sl[0].get('duplicates'),
                  'conns': sl[0].get('connectionsAccepted'), 'status': (status or {}).get('status')}))
PY
for f in /var/lib/bower-lab/snap/${LABEL}*; do aws s3 cp "$f" "s3://$B/results/$(hostname -s)/$(basename "$f")" --region "$R" --only-show-errors; done
