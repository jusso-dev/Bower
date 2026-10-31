#!/usr/bin/env python3
"""Live syslog mutual-TLS rotation and rejection campaign for one disposable Linux host.

Runs as root on an owned lab host: `--phase setup` (after `syslog-tls-setup.sh` installed
rsyslog and extracted the collector and signed pack), then `--phase campaign`. A real rsyslog sender
forwards generated RFC 5424 frames over mutual TLS to a real Bower collector. The
script issues every certificate and revocation list with `openssl ca`, rotates them
while traffic flows, and reconciles the exact sequence numbers Bower queued. Each
frame carries its sequence number in a synthetic 10.x source address, so the queue
proves which frames arrived without storing message text.

Output is metadata only (counts, counters, certificate fingerprints, timings). Keys
stay on the host under /etc/bower-ws5 (0700) and are never printed.
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import time
import urllib.request

BASE = '/etc/bower-ws5'
PKI = f'{BASE}/pki'
TLS = f'{BASE}/tls'
CLIENT = f'{BASE}/rsyslog'
STATE = '/var/lib/bower-ws5'
QUEUE = f'{STATE}/queue/bower.db'
REPORT = f'{STATE}/report'
STATUS_URL = 'http://127.0.0.1:4318/v1/status'
GENERATOR = ('127.0.0.1', 10514)
LISTENER = ('127.0.0.1', 6514)
PEER = 'collector.lab'


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def run(*args, check=True, quiet=True):
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode != 0:
        # Command names only: never echo output that could include key material.
        raise SystemExit(f'command failed: {args[0]} {args[1] if len(args) > 1 else ""} ({result.returncode})')
    return result


def write(path, text, mode=0o600, owner=None):
    staging = path + '.new'
    with open(staging, 'w') as handle:
        handle.write(text)
    os.chmod(staging, mode)
    if owner:
        shutil.chown(staging, owner, owner)
    os.replace(staging, path)


def fingerprint(path):
    out = run('openssl', 'x509', '-in', path, '-noout', '-fingerprint', '-sha256').stdout
    return out.strip().split('=', 1)[1].replace(':', '').lower()


# ---------- PKI with openssl ca ----------

CA_CONFIG = """[ ca ]
default_ca = local
[ local ]
dir = {dir}
database = $dir/index.txt
new_certs_dir = $dir/issued
serial = $dir/serial
crlnumber = $dir/crlnumber
certificate = $dir/ca.crt
private_key = $dir/ca.key
default_md = sha256
default_days = 10
default_crl_days = 7
policy = any
unique_subject = no
copy_extensions = none
crl_extensions = crl_ext
[ any ]
commonName = supplied
[ client_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
authorityKeyIdentifier = keyid
[ server_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:collector.lab,IP:127.0.0.1
authorityKeyIdentifier = keyid
[ wrong_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:wrong.lab
authorityKeyIdentifier = keyid
[ crl_ext ]
authorityKeyIdentifier = keyid
"""


def make_ca(name):
    directory = f'{PKI}/{name}'
    os.makedirs(f'{directory}/issued', mode=0o700, exist_ok=True)
    write(f'{directory}/index.txt', '')
    write(f'{directory}/serial', os.urandom(8).hex() + '\n')
    write(f'{directory}/crlnumber', '01\n')
    write(f'{directory}/openssl.cnf', CA_CONFIG.format(dir=directory))
    run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
        '-keyout', f'{directory}/ca.key', '-out', f'{directory}/ca.crt', '-days', '30', '-subj', f'/CN={name}',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
        '-addext', 'subjectKeyIdentifier=hash')
    return directory


def issue(ca, name, extension, start=None, end=None):
    directory = f'{PKI}/{os.path.basename(ca)}-{name}'
    os.makedirs(directory, mode=0o700, exist_ok=True)
    run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', f'{directory}/key.pem')
    run('openssl', 'req', '-new', '-key', f'{directory}/key.pem', '-subj', f'/CN={name}', '-out', f'{directory}/req.pem')
    args = ['openssl', 'ca', '-batch', '-notext', '-config', f'{ca}/openssl.cnf', '-extensions', extension,
            '-in', f'{directory}/req.pem', '-out', f'{directory}/cert.pem']
    if start:
        args += ['-startdate', start, '-enddate', end]
    run(*args)
    return directory


def revoke(ca, issued):
    run('openssl', 'ca', '-batch', '-config', f'{ca}/openssl.cnf', '-revoke', f'{issued}/cert.pem')


def crl(ca):
    run('openssl', 'ca', '-batch', '-config', f'{ca}/openssl.cnf', '-gencrl', '-out', f'{ca}/crl.pem')
    with open(f'{ca}/crl.pem') as handle:
        return handle.read()


def read(path):
    with open(path) as handle:
        return handle.read()


# ---------- Bower and rsyslog control ----------

def token():
    return read(f'{BASE}/ingest-token').strip()


def status():
    request = urllib.request.Request(STATUS_URL, headers={'Authorization': 'Bearer ' + token()})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.load(response)
    listener = body['syslog'][0]
    keys = ['activeConnections', 'connectionsAccepted', 'tlsHandshakeFailures', 'tlsReloads', 'tlsReloadFailures',
            'tlsRevoked', 'tlsSessionsClosed', 'framesReceived', 'queued', 'duplicates', 'parserErrors', 'malformed',
            'oversized', 'framingErrors', 'timeouts', 'dropped', 'notRouted', 'notSelected', 'rejected',
            'serverCertificateNotAfter', 'clientCertificateAuthorityNotAfter', 'clientRevocationListNextUpdate']
    return {key: listener.get(key) for key in keys} | {'queue': body['queue']}


def wait_status(condition, timeout=60):
    deadline = time.monotonic() + timeout
    value = status()
    while not condition(value):
        if time.monotonic() > deadline:
            return value, False
        time.sleep(0.5)
        value = status()
    return value, True


def server_files(issued):
    # Key first, then certificate, each atomically renamed: the reload never sees a torn file.
    write(f'{TLS}/server-key.pem', read(f'{issued}/key.pem'), 0o640, 'bower')
    write(f'{TLS}/server.pem', read(f'{issued}/cert.pem'), 0o644, 'bower')


def authorities(*cas):
    write(f'{TLS}/client-ca.pem', ''.join(read(f'{ca}/ca.crt') for ca in cas), 0o644, 'bower')


def revocations(*cas):
    write(f'{TLS}/client-ca.crl', ''.join(crl(ca) for ca in cas), 0o644, 'bower')


def sender_identity(issued):
    write(f'{CLIENT}/client.pem', read(f'{issued}/cert.pem'))
    write(f'{CLIENT}/client-key.pem', read(f'{issued}/key.pem'))


def restart(unit):
    run('systemctl', 'restart', unit)


def queued_sequences():
    """Sequence numbers present in the durable queue, read from the synthetic source address."""
    connection = sqlite3.connect(f'file:{QUEUE}?mode=ro', uri=True, timeout=30)
    try:
        rows = connection.execute('SELECT payload FROM queue_events').fetchall()
    finally:
        connection.close()
    sequences = set()
    for (payload,) in rows:
        address = json.loads(payload).get('source', {}).get('ipAddress', '')
        parts = address.split('.')
        if len(parts) == 4 and parts[0] == '10':
            sequences.add((int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3]))
    return sequences


class Generator:
    """Plain loopback TCP to rsyslog's imtcp input; rsyslog owns the TLS session to Bower."""

    def __init__(self, start):
        self.next = start

    def send(self, count, rate):
        sent = []
        with socket.create_connection(GENERATOR, timeout=10) as connection:
            interval = 1.0 / rate
            began = time.monotonic()
            for index in range(count):
                sequence = self.next
                self.next += 1
                address = f'10.{(sequence >> 16) & 255}.{(sequence >> 8) & 255}.{sequence & 255}'
                stamp = now().isoformat(timespec='microseconds').replace('+00:00', 'Z')
                message = (f'<12>1 {stamp} firewall-lab nftables - - - BOWER_DENY seq={sequence} IN=bwf0 OUT= '
                           f'SRC={address} DST=172.19.0.1 PROTO=UDP DPT=4444 ')
                frame = message.encode()
                connection.sendall(f'{len(frame)} '.encode() + frame)
                sent.append(sequence)
                delay = began + (index + 1) * interval - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
        return sent


def handshake(certificate=None, key=None, authority=None, hostname=None):
    """One TLS handshake plus a probe read; True only if the server kept the session."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(authority or f'{PKI}/server-ca/ca.crt')
    context.check_hostname = hostname is not None
    if certificate:
        context.load_cert_chain(certificate, key)
    try:
        with socket.create_connection(LISTENER, timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname or PEER) as secure:
                served = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
                secure.settimeout(1.5)
                try:
                    # TLS 1.3 reports a refused client certificate on the first read.
                    if secure.recv(1) == b'':
                        return False, served
                except socket.timeout:
                    return True, served
                return True, served
    except (ssl.SSLError, ConnectionError, OSError) as error:
        return False, type(error).__name__


def settle(expected, timeout=120):
    deadline = time.monotonic() + timeout
    while True:
        present = queued_sequences()
        missing = sorted(set(expected) - present)
        if not missing or time.monotonic() > deadline:
            return present, missing
        time.sleep(1)


def journal_count(unit, pattern, since):
    out = run('journalctl', '-u', unit, '--since', since, '--no-pager', '-o', 'cat', check=False).stdout
    return sum(1 for line in out.splitlines() if pattern in line)


# ---------- Setup ----------

RSYSLOG = """# Bower ws5 lab: loopback generator input, mutual-TLS forwarding to Bower.
global(DefaultNetstreamDriverCAFile="{client}/server-ca.pem"
       DefaultNetstreamDriverCertFile="{client}/client.pem"
       DefaultNetstreamDriverKeyFile="{client}/client-key.pem")
module(load="imtcp" StreamDriver.Name="ptcp" StreamDriver.Mode="0")
input(type="imtcp" address="127.0.0.1" port="10514" ruleset="bower_ws5")
ruleset(name="bower_ws5") {{
  action(type="omfwd" target="127.0.0.1" port="6514" protocol="tcp"
         template="RSYSLOG_SyslogProtocol23Format" TCP_Framing="octet-counted"
         StreamDriver="ossl" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
         StreamDriverPermittedPeers="collector.lab" RebindInterval="0"
         queue.type="LinkedList" queue.filename="bower_ws5" queue.saveOnShutdown="on"
         queue.size="100000" action.resumeRetryCount="-1" action.resumeInterval="2")
}}
"""

UNIT = """[Unit]
Description=Bower ws5 lab collector
After=network-online.target
[Service]
User=bower
Group=bower
EnvironmentFile={base}/collector.env
WorkingDirectory={state}
ExecStart=/opt/bower/collector/Bower.Collector
Restart=on-failure
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
"""


def setup(run_id):
    for path, mode in [(BASE, 0o755), (PKI, 0o700), (TLS, 0o750), (CLIENT, 0o700), (STATE, 0o750), (f'{STATE}/queue', 0o750)]:
        os.makedirs(path, mode=mode, exist_ok=True)
        os.chmod(path, mode)
    for path in (TLS, STATE, f'{STATE}/queue'):
        shutil.chown(path, 'root' if path == TLS else 'bower', 'bower')
    server_ca = make_ca('server-ca')
    for name in ('s1', 's2'):
        issue(server_ca, name, 'server_ext')
    issue(server_ca, 'wrong', 'wrong_ext')
    client_a, client_b, rogue = make_ca('client-a'), make_ca('client-b'), make_ca('rogue')
    issue(client_a, 'a1', 'client_ext')
    for name in ('b1', 'b2'):
        issue(client_b, name, 'client_ext')
    issue(client_b, 'expired', 'client_ext', start='20261001000000Z', end='20261020000000Z')
    issue(client_b, 'serverpurpose', 'server_ext')
    issue(rogue, 'r1', 'client_ext')
    server_files(f'{server_ca}-s1')
    authorities(client_a)
    # Empty, signed lists for both client CAs: revocation is enforced from the start.
    revocations(client_a, client_b)
    write(f'{CLIENT}/server-ca.pem', read(f'{server_ca}/ca.crt'))
    sender_identity(f'{client_a}-a1')
    write(f'{BASE}/ingest-token', os.urandom(32).hex(), 0o640, None)
    shutil.chown(f'{BASE}/ingest-token', 'root', 'bower')
    config = {'apiVersion': 'bower.security/v1', 'kind': 'SyslogSource', 'listeners': [{
        'id': 'edge-tls', 'protocol': 'tls', 'address': '127.0.0.1', 'port': 6514,
        'allowedSenders': ['127.0.0.1'], 'idleTimeoutSeconds': 3600, 'maximumConnections': 64,
        'tls': {'certificateFile': f'{TLS}/server.pem', 'privateKeyFile': f'{TLS}/server-key.pem',
                'clientCertificateAuthorityFile': f'{TLS}/client-ca.pem',
                'clientCertificateRevocationListFile': f'{TLS}/client-ca.crl'},
        'routes': [{'appName': 'nftables', 'pack': 'nftables-validation', 'parser': 0}]}]}
    write(f'{BASE}/syslog.json', json.dumps(config, indent=1), 0o644)
    environment = {
        'BOWER_LISTEN_URL': 'http://127.0.0.1:4318', 'BOWER_QUEUE_PATH': QUEUE,
        'BOWER_PACKS': f'{BASE}/packs/nftables-validation-1.0.0.bowerpack',
        'BOWER_PACK_TRUSTED_KEYS': f'{BASE}/keys/pack-trusted.pem', 'BOWER_SYSLOG_CONFIG': f'{BASE}/syslog.json',
        'BOWER_INGEST_TOKEN_FILE': f'{BASE}/ingest-token', 'BOWER_OUTPUT': 'none',
        'BOWER_COLLECTOR_ID': f'{run_id}-syslog', 'BOWER_ENVIRONMENT': 'ws5-lab',
        'BOWER_POLICY_DIRECTORY': f'{BASE}/no-local-policies'}
    write(f'{BASE}/collector.env', ''.join(f'{key}={value}\n' for key, value in environment.items()), 0o644)
    write('/etc/systemd/system/bower-ws5-collector.service', UNIT.format(base=BASE, state=STATE), 0o644)
    write('/etc/rsyslog.d/30-bower-ws5.conf', RSYSLOG.format(client=CLIENT), 0o644)
    run('rsyslogd', '-N1')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'bower-ws5-collector')
    wait_ready()
    restart('rsyslog')
    print(json.dumps({'setup': 'complete', 'serverSha256': fingerprint(f'{TLS}/server.pem')}))


def wait_ready(timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return status()
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def refusal_tls12(run_id, rate):
    """Repeats emergency revocation with the sender capped at TLS 1.2.

    Under TLS 1.3 a client learns that its certificate was refused only after the
    handshake, so rsyslog writes a frame into each doomed session. Under TLS 1.2 the
    refusal ends the handshake itself and rsyslog keeps the frame queued.
    """
    report_path = f'{REPORT}/syslog-tls12-refusal.json'
    conf = '/etc/rsyslog.d/30-bower-ws5.conf'
    original = read(conf)
    write(conf, original.replace('RebindInterval="0"', 'RebindInterval="0" gnutlsPriorityString="MaxProtocol=TLSv1.2"'), 0o644)
    run('rsyslogd', '-N1')
    client_b = f'{PKI}/client-b'
    current = issue(client_b, 'tls12-a', 'client_ext')
    successor = issue(client_b, 'tls12-b', 'client_ext')
    sender_identity(current)
    restart('rsyslog')
    generator = Generator(start=max(queued_sequences() | {0}) + 1000)
    started = now()
    before = status()
    sent_before = generator.send(30, rate)
    revoke(client_b, current)
    mid = status()
    revocations(client_b)
    wait_status(lambda value: value['tlsReloads'] >= mid['tlsReloads'] + 1, 30)
    during = generator.send(40, rate)
    _, closed = wait_status(lambda value: value['tlsSessionsClosed'] >= mid['tlsSessionsClosed'] + 1, 30)
    time.sleep(10)
    during_present = len(queued_sequences() & set(during))
    sender_identity(successor)
    restart('rsyslog')
    sent_after = generator.send(30, rate)
    sent = sent_before + during + sent_after
    present, missing = settle(sent)
    after = status()
    result = {'phase': 'emergency-client-revocation-tls12', 'runId': run_id, 'startedAt': started.isoformat(),
              'endedAt': now().isoformat(), 'sent': len(sent), 'accepted': len(set(sent) & present),
              'missing': len(missing), 'missingSample': missing[:20], 'sessionClosed': closed,
              'acceptedWhileRevoked': during_present,
              'handshakesRefusedAsRevoked': after['tlsRevoked'] - before['tlsRevoked'],
              'duplicates': after['duplicates'] - before['duplicates'], 'status': after,
              'rsyslogTlsErrors': journal_count('rsyslog', 'error', started.strftime('%Y-%m-%d %H:%M:%S'))}
    write(conf, original, 0o644)
    restart('rsyslog')
    write(report_path, json.dumps(result, indent=1))
    print(json.dumps({key: result[key] for key in ('sent', 'accepted', 'missing', 'acceptedWhileRevoked', 'handshakesRefusedAsRevoked', 'duplicates')}))


# ---------- Campaign ----------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--phase', choices=['setup', 'campaign', 'refusal-tls12'], required=True)
    parser.add_argument('--rate', type=int, default=10)
    arguments = parser.parse_args()
    if arguments.phase == 'setup':
        setup(arguments.run_id)
        return
    if arguments.phase == 'refusal-tls12':
        refusal_tls12(arguments.run_id, arguments.rate)
        return
    os.makedirs(REPORT, mode=0o700, exist_ok=True)
    phases = []
    report = {'runId': arguments.run_id, 'host': socket.gethostname(), 'startedAt': now().isoformat(), 'phases': phases,
              'rsyslog': run('rpm', '-q', 'rsyslog', check=False).stdout.strip(),
              'openssl': run('openssl', 'version').stdout.strip()}

    def record(name, sent, started, note, **extra):
        present, missing = settle(sent)
        phase = {'phase': name, 'note': note, 'sent': len(sent), 'accepted': len(set(sent) & present),
                 'missing': len(missing), 'missingSample': missing[:20], 'status': status(),
                 'startedAt': started.isoformat(), 'endedAt': now().isoformat()} | extra
        phases.append(phase)
        write(f'{REPORT}/syslog-tls-rotation.json', json.dumps(report, indent=1))
        print(json.dumps({'phase': name, 'sent': phase['sent'], 'accepted': phase['accepted'], 'missing': phase['missing']}))
        return phase

    generator = Generator(start=1)
    rate = arguments.rate

    # P0 baseline: persistent rsyslog session, server S1, client CA A, client cert A1.
    started = now()
    before = status()
    sent = generator.send(100, rate)
    record('baseline', sent, started, 'rsyslog persistent mTLS session, no rotation',
           connectionsDuring=status()['connectionsAccepted'] - before['connectionsAccepted'])

    # P1 server certificate rotation while the session carries traffic.
    started = now()
    before = status()
    old_print = fingerprint(f'{TLS}/server.pem')
    sent = generator.send(40, rate)
    server_files(f'{PKI}/server-ca-s2')
    reloaded, ok = wait_status(lambda value: value['tlsReloads'] >= before['tlsReloads'] + 1, 30)
    sent += generator.send(60, rate)
    accepted_new, served = handshake(f'{PKI}/client-a-a1/cert.pem', f'{PKI}/client-a-a1/key.pem', hostname=PEER)
    record('server-certificate-hot-rotation', sent, started,
           'server certificate and key replaced by atomic rename during traffic; no collector or sender restart',
           reloadApplied=ok, previousServerSha256=old_print, newServerSha256=fingerprint(f'{TLS}/server.pem'),
           newHandshakeServedSha256=served, newHandshakeAccepted=accepted_new,
           senderReconnects=status()['connectionsAccepted'] - before['connectionsAccepted'] - 1)

    # P2 client CA overlap: bundle A+B, move the sender to a B certificate, then remove A.
    started = now()
    before = status()
    authorities(f'{PKI}/client-a', f'{PKI}/client-b')
    wait_status(lambda value: value['tlsReloads'] >= before['tlsReloads'] + 1, 30)
    sent = generator.send(30, rate)
    sender_identity(f'{PKI}/client-b-b1')
    restart('rsyslog')
    sent += generator.send(30, rate)
    mid = status()
    authorities(f'{PKI}/client-b')
    wait_status(lambda value: value['tlsReloads'] >= mid['tlsReloads'] + 1, 30)
    sent += generator.send(40, rate)
    old_refused, _ = handshake(f'{PKI}/client-a-a1/cert.pem', f'{PKI}/client-a-a1/key.pem', hostname=PEER)
    new_accepted, _ = handshake(f'{PKI}/client-b-b2/cert.pem', f'{PKI}/client-b-b2/key.pem', hostname=PEER)
    record('client-ca-overlap-rotation', sent, started,
           'bundle A+B, sender restarted with a CA-B certificate (rsyslog queue saved), then CA-A removed',
           oldAuthorityHandshakeAccepted=old_refused, newAuthorityHandshakeAccepted=new_accepted)

    # P3 revocation lists: an empty list, then emergency revocation of the connected sender.
    started = now()
    sent_before = generator.send(30, rate)
    revoke(f'{PKI}/client-b', f'{PKI}/client-b-b1')
    mid = status()
    revocations(f'{PKI}/client-b')
    wait_status(lambda value: value['tlsReloads'] >= mid['tlsReloads'] + 1, 30)
    revoked_at = now()
    during = generator.send(40, rate)
    closed, closed_ok = wait_status(lambda value: value['tlsSessionsClosed'] >= mid['tlsSessionsClosed'] + 1, 30)
    _, revoked_wait = wait_status(lambda value: value['tlsRevoked'] >= mid['tlsRevoked'] + 1, 60)
    revoked_handshake, _ = handshake(f'{PKI}/client-b-b1/cert.pem', f'{PKI}/client-b-b1/key.pem', hostname=PEER)
    during_present = queued_sequences() & set(during)
    # Re-issue the sender's certificate and restart rsyslog: its saved queue replays.
    sender_identity(f'{PKI}/client-b-b2')
    restart('rsyslog')
    sent_after = generator.send(30, rate)
    record('emergency-client-revocation', sent_before + during + sent_after, started,
           'connected sender revoked by a reloaded CRL; session closed; reconnects refused; re-issued certificate replays rsyslog queue',
           sessionClosed=closed_ok, reconnectRefusedAsRevoked=revoked_wait, revokedHandshakeAccepted=revoked_handshake,
           acceptedWhileRevoked=len(during_present), revokedAt=revoked_at.isoformat(),
           rsyslogTlsErrors=journal_count('rsyslog', 'error', started.strftime('%Y-%m-%d %H:%M:%S')))

    # P4 refused certificates (no sender restart; direct handshakes).
    refused = {}
    for name, files in [('expired-client', 'client-b-expired'), ('untrusted-client', 'rogue-r1'),
                        ('revoked-client', 'client-b-b1'), ('server-purpose-as-client', 'client-b-serverpurpose'),
                        ('removed-authority-client', 'client-a-a1')]:
        accepted, _ = handshake(f'{PKI}/{files}/cert.pem', f'{PKI}/{files}/key.pem', hostname=PEER)
        refused[name] = not accepted
    accepted, _ = handshake(None, None, hostname=PEER)
    refused['no-client-certificate'] = not accepted
    phases.append({'phase': 'refused-client-certificates', 'refused': refused, 'status': status()})

    # P5 wrong server name: the sender refuses a certificate for another name and queues.
    started = now()
    before = status()
    server_files(f'{PKI}/server-ca-wrong')
    wait_status(lambda value: value['tlsReloads'] >= before['tlsReloads'] + 1, 30)
    restart('rsyslog')
    wrong = generator.send(30, rate)
    time.sleep(10)
    accepted_during_wrong = len(queued_sequences() & set(wrong))
    name_check, _ = handshake(None, None, hostname=PEER)
    server_files(f'{PKI}/server-ca-s2')
    record('wrong-server-name', wrong, started,
           'server certificate for wrong.lab: rsyslog x509/name check refused it; frames queued at the sender until the right certificate returned',
           acceptedWhileWrongName=accepted_during_wrong, pythonNameCheckAccepted=name_check)

    # P6 failed reload keeps the last good material.
    before = status()
    # A key that does not match the certificate (a half-finished manual rotation).
    write(f'{TLS}/server-key.pem', read(f'{PKI}/server-ca-s1/key.pem'), 0o640, 'bower')
    failed, failed_ok = wait_status(lambda value: value['tlsReloadFailures'] >= before['tlsReloadFailures'] + 1, 30)
    still, served = handshake(f'{PKI}/client-b-b2/cert.pem', f'{PKI}/client-b-b2/key.pem', hostname=PEER)
    server_files(f'{PKI}/server-ca-s2')
    phases.append({'phase': 'failed-reload', 'failureCounted': failed_ok, 'handshakeStillAccepted': still,
                   'servedSha256': served, 'status': status()})

    # P7 collector restart during traffic (what restart-based rotation costs this sender).
    started = now()
    sent = generator.send(30, rate)
    restart('bower-ws5-collector')
    sent += generator.send(70, rate)
    wait_ready()
    record('collector-restart-under-load', sent, started,
           'systemctl restart of the collector while rsyslog streams at the campaign rate',
           restartedAt=started.isoformat())

    report['endedAt'] = now().isoformat()
    write(f'{REPORT}/syslog-tls-rotation.json', json.dumps(report, indent=1))
    print(json.dumps({'done': True, 'phases': len(phases)}))


if __name__ == '__main__':
    main()
