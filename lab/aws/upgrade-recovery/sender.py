#!/usr/bin/env python3
"""Sequence-numbered RFC 5424 sender over mutual TLS (synthetic lab traffic only).

Frame N is a pure function of (stream, base time, rate, N), so the collector event id
(sha256(listener, sender address, frame)) of every sequence number can be recomputed.
On reconnect it resends the last RESEND frames it wrote (bounded at-least-once window);
the collector deduplicates identical frames. Writes metadata-only progress JSON.
"""
import argparse
import collections
import datetime as dt
import json
import os
import socket
import ssl
import time

p = argparse.ArgumentParser()
p.add_argument('--stream', required=True)
p.add_argument('--target', required=True)
p.add_argument('--port', type=int, default=6514)
p.add_argument('--rate', type=int, default=20)
p.add_argument('--start', type=int, default=0)
p.add_argument('--count', type=int, required=True)
p.add_argument('--base', required=True, help='UTC base time for sequence 0, ISO 8601')
p.add_argument('--resend', type=int, default=1200)
p.add_argument('--state', default='/var/lib/bower-sender')
a = p.parse_args()
assert 1 <= a.rate <= 200 and 0 < a.count <= 500_000 and a.resend >= 0

base = dt.datetime.fromisoformat(a.base.replace('Z', '+00:00'))
os.makedirs(a.state, mode=0o700, exist_ok=True)
progress_path = os.path.join(a.state, a.stream + '.json')


def frame(n):
    ts = (base + dt.timedelta(microseconds=round(n * 1_000_000 / a.rate))).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    msg = (f'<134>1 {ts} bower-firewall nftables - DENY - BOWER_DENY IN=eth0 OUT= SRC=172.19.0.2 '
           f'DST=172.19.0.1 PROTO=UDP SPT={10000 + n % 50000} DPT=4444 STREAM={a.stream} SEQ={n}')
    return msg.encode() + b'\n'


context = ssl.create_default_context(cafile='/etc/bower-sender/ca.pem')
context.load_cert_chain('/etc/bower-sender/client.pem', '/etc/bower-sender/client.key')
stats = collections.Counter()
recent = collections.deque(maxlen=max(a.resend, 1))
sock = None
started = time.time()
next_seq = a.start
end = a.start + a.count
last_write = 0.0


def save(final=False):
    data = {'stream': a.stream, 'target': a.target, 'base': a.base, 'rate': a.rate, 'start': a.start,
            'count': a.count, 'nextSequence': next_seq, 'final': final, 'resendWindow': a.resend,
            'updatedAt': dt.datetime.now(dt.timezone.utc).isoformat(), **stats}
    tmp = progress_path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f)
    os.replace(tmp, progress_path)


def connect():
    global sock
    while True:
        try:
            raw = socket.create_connection((a.target, a.port), timeout=5)
            # Fail writes that stay unacknowledged for 15 s (host power loss sends no RST),
            # so the resend window (> 15 s of traffic) covers every frame that may be lost.
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 15000)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock = context.wrap_socket(raw, server_hostname='bower-syslog')
            sock.settimeout(10)
            stats['connections'] += 1
            for item in list(recent):
                sock.sendall(item)
                stats['resent'] += 1
            return
        except (OSError, ssl.SSLError):
            stats['connectFailures'] += 1
            sock = None
            time.sleep(1)


connect()
while next_seq < end:
    due = started + (next_seq - a.start) / a.rate
    delay = due - time.time()
    if delay > 0:
        time.sleep(delay)
    data = frame(next_seq)
    try:
        sock.sendall(data)
        recent.append(data)
        stats['sent'] += 1
        next_seq += 1
    except (OSError, ssl.SSLError):
        stats['sendFailures'] += 1
        try:
            sock.close()
        except OSError:
            pass
        connect()
    if time.time() - last_write > 2:
        save()
        last_write = time.time()
try:
    sock.unwrap()
except (OSError, ssl.SSLError, ValueError):
    pass
save(final=True)
print(json.dumps({'stream': a.stream, 'nextSequence': next_seq, **stats}))
