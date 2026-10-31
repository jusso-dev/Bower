"""Expected collector event ids for sender streams (mirrors SyslogRecord.EventId)."""
import datetime as dt, hashlib

def frame(stream, base, rate, n):
    b = dt.datetime.fromisoformat(base.replace('Z', '+00:00'))
    ts = (b + dt.timedelta(microseconds=round(n * 1_000_000 / rate))).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    return (f'<134>1 {ts} bower-firewall nftables - DENY - BOWER_DENY IN=eth0 OUT= SRC=172.19.0.2 '
            f'DST=172.19.0.1 PROTO=UDP SPT={10000 + n % 50000} DPT=4444 STREAM={stream} SEQ={n}').encode()

def event_id(stream, base, rate, n, sender='172.31.244.168', listener='firewall'):
    h = hashlib.sha256(listener.encode() + b'\x1f' + sender.encode() + b'\x1f' + frame(stream, base, rate, n))
    return 'syslog-' + h.hexdigest()[:32]
