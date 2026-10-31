#!/usr/bin/env python3
"""Adversarial syslog campaign against a live Bower mutual-TLS listener (root, lab host).

Requires `syslog-tls-rotation.py --phase setup` first. Adds a `fuzz` listener (port
6515, 5 s idle timeout, 8 connections, 8 KiB frames) beside the campaign listener,
restarts the collector once, then sends hostile frames with a valid client certificate.
Every frame embeds synthetic secret markers in each syslog field; afterwards the queue
database, WAL and SHM, the collector journal and the status output are scanned for the
raw markers. Output is metadata only: counter deltas, outcomes and match counts.
"""
import argparse
import datetime
import json
import os
import socket
import ssl
import subprocess
import threading
import time
import urllib.request

BASE = '/etc/bower-ws5'
PKI = f'{BASE}/pki'
STATE = '/var/lib/bower-ws5'
REPORT = f'{STATE}/report/syslog-adversarial.json'
FUZZ = ('127.0.0.1', 6515)
CLIENT = f'{PKI}/client-b-b2'

# Synthetic markers from the redaction corpus and campaign-unique sentinels. None is real.
SECRETS = {
    'aws': 'AKIAIOSFODNN7EXAMPLE',
    'jwt': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl',
    'github': 'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    'tfn': '100000001',
    'card': '4111111111111111',
    'password': 'P@ssw0rd-ws5-sentinel',
    'sentinel': 'BOWER_WS5_SECRET_SENTINEL',
}
INJECTION = ['=HYPERLINK("http://evil.invalid","x")', "+cmd|' /C calc'!A0", '@SUM(1+1)',
             '" | where 1==1 //', "'; drop table x; --", '‮txt.exe', '\x1b[31mred\x1b[0m']


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def status():
    token = open(f'{BASE}/ingest-token').read().strip()
    request = urllib.request.Request('http://127.0.0.1:4318/v1/status', headers={'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.load(response)
    listener = next(item for item in body['syslog'] if item['id'] == 'fuzz')
    return listener, body


def counters():
    listener, body = status()
    keys = ['activeConnections', 'connectionsAccepted', 'connectionsRejected', 'tlsHandshakeFailures',
            'framesReceived', 'queued', 'duplicates', 'notRouted', 'notSelected', 'rejected', 'parserErrors',
            'malformed', 'oversized', 'framingErrors', 'timeouts', 'dropped']
    return {key: listener[key] for key in keys} | {'queueTotal': body['queue']['queued']}


def delta(before, after):
    return {key: after[key] - before[key] for key in before if after[key] != before[key]}


def context():
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.load_verify_locations(f'{PKI}/server-ca/ca.crt')
    tls.load_cert_chain(f'{CLIENT}/cert.pem', f'{CLIENT}/key.pem')
    tls.check_hostname = True
    return tls


def connect():
    raw = socket.create_connection(FUZZ, timeout=10)
    return context().wrap_socket(raw, server_hostname='collector.lab')


def closed_by_server(secure, wait=8):
    secure.settimeout(wait)
    try:
        return secure.recv(1) == b''
    except (socket.timeout, TimeoutError):
        return False
    except (ssl.SSLError, ConnectionError, OSError):
        return True


def octet(frame: bytes) -> bytes:
    return str(len(frame)).encode() + b' ' + frame


def frame(sequence, message=b'', hostname=b'fw-lab', app=b'nftables', procid=b'-', msgid=b'-', sd=b'-'):
    address = f'10.200.{(sequence >> 8) & 255}.{sequence & 255}'.encode()
    stamp = now().isoformat(timespec='microseconds').replace('+00:00', 'Z').encode()
    body = (b'BOWER_DENY seq=%d IN=bwf0 OUT= SRC=' % sequence) + address + b' DST=172.19.0.1 ' + message
    return b'<12>1 ' + stamp + b' ' + hostname + b' ' + app + b' ' + procid + b' ' + msgid + b' ' + sd + b' ' + body


def case(name, action, results):
    before = counters()
    started = time.monotonic()
    outcome = action()
    time.sleep(1.5)
    after = counters()
    results.append({'case': name, 'outcome': outcome, 'counterDelta': delta(before, after),
                    'seconds': round(time.monotonic() - started, 3)})
    print(json.dumps({'case': name, 'outcome': outcome, 'delta': results[-1]['counterDelta']}))


def secrets_everywhere(sequence):
    hostname = SECRETS['aws'].encode()
    sd = ('[x@32473 password="%s" token="%s" card="%s"]' % (SECRETS['password'], SECRETS['jwt'], SECRETS['card'])).encode()
    message = ('github=%s tfn=%s sentinel=%s' % (SECRETS['github'], SECRETS['tfn'], SECRETS['sentinel'])).encode()
    return frame(sequence, message, hostname=hostname, procid=SECRETS['sentinel'].encode(), msgid=b'TFN' + SECRETS['tfn'].encode(), sd=sd)


def run_cases():
    results = []
    sequence = iter(range(1, 100000))

    def send(frames, expect_close=False):
        with connect() as secure:
            for item in frames:
                secure.sendall(item)
            return {'serverClosed': closed_by_server(secure, 6 if expect_close else 2)}

    case('baseline-valid', lambda: send([octet(frame(next(sequence))) for _ in range(5)]), results)
    case('secrets-in-every-field', lambda: send([octet(secrets_everywhere(next(sequence))) for _ in range(5)]), results)
    case('injection-strings', lambda: send([octet(frame(next(sequence), value.encode(), hostname=b'=1+1')) for value in INJECTION]), results)
    case('nul-control-ansi', lambda: send([octet(frame(next(sequence), b'a\x00b\x07c\x1b[2Jd\x7f'))]), results)
    case('invalid-utf8', lambda: send([octet(frame(next(sequence), b'\xff\xfe\xc0\xaf\xed\xa0\x80'))]), results)
    case('crlf-injection-line-framed', lambda: send([frame(next(sequence), b'x\r\n<12>1 - forged nftables - - - BOWER_DENY SRC=10.250.0.1 \n')]), results)
    case('embedded-newline-octet-framed', lambda: send([octet(frame(next(sequence), b'line1\nline2\r\nline3'))]), results)
    case('huge-structured-data', lambda: send([octet(frame(next(sequence), sd=b''.join(b'[s%d@1 p="%s"]' % (i, b'v' * 30) for i in range(150))))]), results)
    case('deeply-nested-json-message', lambda: send([octet(frame(next(sequence), b'{"a":' * 1500 + b'1' + b'}' * 1500))], expect_close=True), results)
    case('oversized-frame', lambda: send([octet(frame(next(sequence), b'x' * 9000))], expect_close=True), results)
    case('octet-count-larger-than-sent', lambda: send([b'500 ' + frame(next(sequence))], expect_close=True), results)
    case('octet-count-overflow', lambda: send([b'99999999999999999999 ' + frame(next(sequence))], expect_close=True), results)
    case('octet-count-zero-and-negative', lambda: send([b'0 ', b'-5 abc'], expect_close=True), results)
    case('non-numeric-garbage', lambda: send([b'\x16\x03\x01garbage\n'], expect_close=True), results)

    def slowloris():
        with connect() as secure:
            payload = octet(frame(next(sequence)))
            started = time.monotonic()
            for byte in payload[:40]:
                try:
                    secure.sendall(bytes([byte]))
                except (ssl.SSLError, OSError):
                    return {'closedAfterSeconds': round(time.monotonic() - started, 1)}
                time.sleep(1)
            return {'closedAfterSeconds': None}
    case('slowloris-one-byte-per-second', slowloris, results)

    def connection_flood():
        held, refused = [], 0
        for _ in range(40):
            try:
                held.append(connect())
            except (ssl.SSLError, OSError):
                refused += 1
        time.sleep(1)
        alive = sum(1 for item in held if not closed_by_server(item, 0.5))
        for item in held:
            item.close()
        time.sleep(1)
        after = send([octet(frame(next(sequence)))])
        return {'attempted': 40, 'handshakeRefused': refused, 'aliveAfterLimit': alive, 'legitimateAfterFlood': after}
    case('tls-connection-flood', connection_flood, results)

    def handshake_flood():
        sockets = [socket.create_connection(FUZZ, timeout=10) for _ in range(6)]
        time.sleep(7)
        closed = 0
        for item in sockets:
            item.settimeout(1)
            try:
                closed += item.recv(1) == b''
            except (socket.timeout, OSError):
                pass
            item.close()
        return {'idleHandshakes': 6, 'closedByServer': closed}
    case('incomplete-handshake-flood', handshake_flood, results)

    def burst():
        with connect() as secure:
            secure.sendall(b''.join(octet(frame(next(sequence))) for _ in range(1000)))
            return {'serverClosed': closed_by_server(secure, 3)}
    case('burst-1000-frames', burst, results)
    return results


def scan():
    """Raw marker matches across durable state, logs and status (counts only)."""
    targets = {}
    for name in ('bower.db', 'bower.db-wal', 'bower.db-shm'):
        path = f'{STATE}/queue/{name}'
        targets[name] = open(path, 'rb').read() if os.path.exists(path) else b''
    targets['collector-journal'] = subprocess.run(
        ['journalctl', '-u', 'bower-ws5-collector', '--no-pager', '-o', 'cat'], capture_output=True).stdout
    _, body = status()
    targets['status'] = json.dumps(body).encode()
    matches = {}
    for target, data in targets.items():
        matches[target] = {key: data.count(value.encode()) for key, value in SECRETS.items()}
        matches[target]['bytes'] = len(data)
    return matches


def configure():
    config = json.load(open(f'{BASE}/syslog.json'))
    if not any(item['id'] == 'fuzz' for item in config['listeners']):
        fuzz = json.loads(json.dumps(config['listeners'][0]))
        fuzz.update({'id': 'fuzz', 'port': 6515, 'idleTimeoutSeconds': 5, 'maximumConnections': 8,
                     'maximumMessageBytes': 8192})
        config['listeners'].append(fuzz)
        with open(f'{BASE}/syslog.json.new', 'w') as handle:
            json.dump(config, handle, indent=1)
        os.chmod(f'{BASE}/syslog.json.new', 0o644)
        os.replace(f'{BASE}/syslog.json.new', f'{BASE}/syslog.json')
        subprocess.run(['systemctl', 'restart', 'bower-ws5-collector'], check=True)
    for _ in range(60):
        try:
            return counters()
        except OSError:
            time.sleep(1)
    raise SystemExit('collector not ready')


def resources():
    pid = subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', 'bower-ws5-collector'],
                         capture_output=True, text=True).stdout.strip()
    rss = next((line.split()[1] for line in open(f'/proc/{pid}/status') if line.startswith('VmRSS:')), None)
    return {'collectorRssKiB': int(rss) if rss else None,
            'active': subprocess.run(['systemctl', 'is-active', 'bower-ws5-collector'], capture_output=True, text=True).stdout.strip()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', required=True)
    arguments = parser.parse_args()
    started = now()
    configure()
    before = resources()
    results = run_cases()
    report = {'runId': arguments.run_id, 'startedAt': started.isoformat(), 'endedAt': now().isoformat(),
              'listener': {'idleTimeoutSeconds': 5, 'maximumConnections': 8, 'maximumMessageBytes': 8192},
              'resourcesBefore': before, 'resourcesAfter': resources(), 'cases': results,
              'finalCounters': counters(), 'markerMatches': scan(),
              'markers': {key: f'{len(value)} chars' for key, value in SECRETS.items()}}
    with open(REPORT, 'w') as handle:
        json.dump(report, handle, indent=1)
    print(json.dumps({'done': True, 'markerMatches': report['markerMatches'], 'resourcesAfter': report['resourcesAfter']}))


if __name__ == '__main__':
    main()
