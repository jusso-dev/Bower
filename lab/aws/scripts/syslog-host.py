#!/usr/bin/env python3
"""Host side of the syslog delivery-reliability lab, driven over SSM by syslog-lab.py.

Collectors run Bower with mutual-TLS syslog listeners; senders run rsyslog (and syslog-ng
in a container) with disk-assisted queues. Generators emit per-event sequence keys, so the
measurement compares exact key sets accepted by the Bower queue. Output is metadata only:
counts, keys of missing events, hashes and settings. Never print private keys, tokens or
queue payloads.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request

LAB = Path("/var/lib/bower-lab")
PKI = Path("/etc/pki/bower-lab")
RESULTS = LAB / "results"
QUEUE = Path("/var/lib/bower/queue.db")
SEQ_DIR = Path("/var/log/bower-seq")
BUCKET = os.environ.get("BOWER_LAB_BUCKET", "")
RUN = os.environ.get("BOWER_LAB_RUN", "")
HOST = os.environ.get("BOWER_LAB_HOST", "")
DOMAIN = "bower.lab"
# Listener id -> (port, idle timeout seconds). Track A runs faults, track B idle gaps.
LISTENERS = {"a13": (6514, 0), "a12": (6516, 0), "b13i": (6514, 3600), "b13n": (6515, 0), "b12i": (6516, 3600)}
NFT_PORT_BASE = {"A": 4400, "B": 4450}
NETNS = "bower-client"


def sh(*args, check=True, capture=True, **kwargs):
    result = subprocess.run(args, check=check, text=True, capture_output=capture, **kwargs)
    return result.stdout.strip() if capture else ""


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def emit(record):
    RESULTS.mkdir(parents=True, exist_ok=True)
    print(json.dumps(record, indent=1, sort_keys=True))


def s3(*args):
    sh("aws", "s3", *args, "--only-show-errors")


def fetch(key, destination, sha256=None):
    s3("cp", "s3://" + BUCKET + "/" + key, str(destination))
    digest = hashlib.sha256(Path(destination).read_bytes()).hexdigest()
    if sha256 and digest != sha256:
        raise RuntimeError(key + " checksum mismatch")
    return digest


def require_lab():
    if not re.fullmatch(r"bower-[a-z0-9]{2,8}-\d{8}-\d{6}", RUN) or os.geteuid() != 0:
        raise RuntimeError("Run only as root on a host of the current lab run")
    LAB.mkdir(mode=0o700, parents=True, exist_ok=True)


def wait_until(epoch):
    delay = epoch - time.time()
    if delay < -5:
        raise RuntimeError("Start time already passed; refusing a stale schedule")
    if delay > 0:
        time.sleep(delay)


# ---------------------------------------------------------------- certificates

def csr(args):
    """Key stays on this host; only the CSR (public) goes to the exchange prefix."""
    PKI.mkdir(mode=0o755, parents=True, exist_ok=True)
    key = PKI / (args.name + "-key.pem")
    if not key.exists():
        old = os.umask(0o077)
        sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key))
        os.umask(old)
    ip = sh("hostname", "-I").split()[0]
    request = LAB / (args.name + ".csr")
    sh("openssl", "req", "-new", "-key", str(key), "-subj", "/CN=" + args.name + "." + DOMAIN,
       "-addext", "subjectAltName=DNS:" + args.name + "." + DOMAIN + ",IP:" + ip, "-out", str(request))
    s3("cp", str(request), "s3://" + BUCKET + "/exchange/" + args.name + ".csr")
    emit({"csr": args.name, "ip": ip, "keyMode": oct(key.stat().st_mode & 0o777)})


def ca(args):
    """Ephemeral lab CA on CollectorA. Its key never leaves this host."""
    PKI.mkdir(mode=0o755, parents=True, exist_ok=True)
    key, cert = PKI / "ca-key.pem", PKI / "ca.pem"
    if not key.exists():
        old = os.umask(0o077)
        sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key))
        os.umask(old)
        sh("openssl", "req", "-x509", "-new", "-key", str(key), "-days", "3", "-subj", "/CN=Bower lab " + RUN,
           "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
           "-out", str(cert))
    s3("cp", str(cert), "s3://" + BUCKET + "/exchange/ca.pem")
    emit({"ca": hashlib.sha256(cert.read_bytes()).hexdigest()})


def sign(args):
    for name in args.names.split(","):
        request = LAB / (name + ".csr")
        fetch("exchange/" + name + ".csr", request)
        usage = "serverAuth" if name.startswith("collector") else "clientAuth"
        extensions = LAB / (name + ".ext")
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                              "extendedKeyUsage=" + usage + "\n")
        cert = LAB / (name + ".pem")
        sh("openssl", "x509", "-req", "-in", str(request), "-CA", str(PKI / "ca.pem"), "-CAkey", str(PKI / "ca-key.pem"),
           "-CAcreateserial", "-days", "2", "-copy_extensions", "copy", "-extfile", str(extensions), "-out", str(cert))
        s3("cp", str(cert), "s3://" + BUCKET + "/exchange/" + name + ".pem")
    emit({"signed": args.names.split(",")})


def install_cert(name, owner=None):
    fetch("exchange/ca.pem", PKI / "ca.pem")
    fetch("exchange/" + name + ".pem", PKI / (name + ".pem"))
    if owner:
        shutil.chown(PKI / (name + "-key.pem"), "root", owner)
        os.chmod(PKI / (name + "-key.pem"), 0o640)


# ---------------------------------------------------------------- collector

def install_collector(args):
    rpm = LAB / "bower.rpm"
    digest = fetch(args.rpm, rpm, args.sha256)
    if subprocess.run(["rpm", "-q", "bower-collector"], capture_output=True).returncode == 0:
        sh("systemctl", "stop", "bower", check=False)
        sh("rpm", "-Uvh", "--force", str(rpm))
    else:
        sh("dnf", "-y", "-q", "install", str(rpm), "python3", "nftables", "tcpdump")
    emit({"installed": sh("rpm", "-q", "bower-collector"), "rpmSha256": digest,
          "collectorSha256": hashlib.sha256(Path("/opt/bower/Bower.Collector").read_bytes()).hexdigest()})


def build_pack(args):
    """Ephemeral pack signing key on CollectorA; the signed pack and public key are public."""
    work = LAB / "pack"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700)
    fetch(args.source, work / "pack.tgz", args.sha256)
    sh("tar", "-xzf", str(work / "pack.tgz"), "-C", str(work))
    keys = work / "keys"
    sh("bower", "keys", "generate", "--out-dir", str(keys), "--name", "lab-pack")
    sh("bower", "pack", "build", str(work / "syslog-reliability"), "--key", str(keys / "lab-pack.key.pem"), "--out", str(work / "out"))
    archive = next((work / "out").glob("*.bowerpack"))
    tested = sh("bower", "pack", "test", str(archive), "--trusted-key", str(keys / "lab-pack.pub.pem"))
    verified = sh("bower", "pack", "verify", str(archive), "--trusted-key", str(keys / "lab-pack.pub.pem"))
    (keys / "lab-pack.key.pem").unlink()
    s3("cp", str(archive), "s3://" + BUCKET + "/exchange/syslog-reliability.bowerpack")
    s3("cp", str(keys / "lab-pack.pub.pem"), "s3://" + BUCKET + "/exchange/lab-pack.pub.pem")
    emit({"pack": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
          "trustedKeySha256": hashlib.sha256((keys / "lab-pack.pub.pem").read_bytes()).hexdigest(),
          "tests": tested.splitlines(), "verified": verified, "signingKeyRemoved": True})


def configure_collector(args):
    name = HOST.lower().replace("collector", "collector-")
    install_cert(name, owner="bower")
    for directory in ("/etc/bower/packs", "/etc/bower/keys", "/etc/bower/secrets", "/var/spool/bower"):
        Path(directory).mkdir(parents=True, exist_ok=True)
    fetch("exchange/syslog-reliability.bowerpack", "/etc/bower/packs/syslog-reliability.bowerpack")
    fetch("exchange/lab-pack.pub.pem", "/etc/bower/keys/lab-pack.pub.pem")
    shutil.chown("/var/spool/bower", "bower", "bower")
    token = Path("/etc/bower/secrets/token")
    if not token.exists():
        old = os.umask(0o027)
        token.write_text(os.urandom(32).hex() + "\n")
        os.umask(old)
    shutil.chown(token, "root", "bower")
    os.chmod(token, 0o640)
    senders = [s for s in args.senders.split(",")]
    listeners = []
    for listener in args.listeners.split(","):
        port, idle = LISTENERS[listener]
        if args.idle is not None:
            idle = args.idle
        options = {"id": listener, "protocol": "tls", "address": "0.0.0.0", "port": port,
                   "allowedSenders": senders, "idleTimeoutSeconds": idle,
                   "tls": {"certificateFile": str(PKI / (name + ".pem")), "privateKeyFile": str(PKI / (name + "-key.pem")),
                           "clientCertificateAuthorityFile": str(PKI / "ca.pem")},
                   "routes": [{"appName": "kernel", "pack": "syslog-reliability", "parser": 0},
                              {"appName": "bowerseq", "pack": "syslog-reliability", "parser": 1}]}
        listeners.append(options)
    Path("/etc/bower/syslog.json").write_text(json.dumps(
        {"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": listeners}, indent=2) + "\n")
    Path("/etc/bower/bower.env").write_text("\n".join([
        "BOWER_COLLECTOR_ID=" + RUN + "-" + name, "BOWER_ENVIRONMENT=validation",
        "BOWER_PACKS=/etc/bower/packs/syslog-reliability.bowerpack", "BOWER_PACK_TRUSTED_KEYS=/etc/bower/keys/lab-pack.pub.pem",
        "BOWER_SYSLOG_CONFIG=/etc/bower/syslog.json", "BOWER_INGEST_TOKEN_FILE=/etc/bower/secrets/token",
        "BOWER_OUTPUT=ama-spool", "BOWER_AMA_SPOOL_PATH=/var/spool/bower", ""]))
    for path in ("/etc/bower/bower.env", "/etc/bower/syslog.json"):
        shutil.chown(path, "root", "bower")
        os.chmod(path, 0o640)
    sh("systemctl", "enable", "bower")
    sh("systemctl", "restart", "bower")
    time.sleep(3)
    emit({"configured": name, "listeners": [{k: l[k] for k in ("id", "port", "idleTimeoutSeconds")} for l in listeners],
          "active": sh("systemctl", "is-active", "bower", check=False), "status": status_summary()})


def status():
    token = Path("/etc/bower/secrets/token").read_text().strip()
    request = urllib.request.Request("http://127.0.0.1:4319/v1/status", headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def status_summary():
    for _ in range(30):
        try:
            return {l["id"]: {k: v for k, v in l.items() if k not in ("id", "protocol", "endpoint")}
                    for l in status().get("syslog") or []}
        except OSError:
            time.sleep(1)
    return None


def queue_keys(prefix):
    if not QUEUE.exists():
        return set(), set()
    with sqlite3.connect("file:" + str(QUEUE) + "?mode=ro", uri=True, timeout=30) as db:
        rows = db.execute("select event_id, delivered_at from queue_events where event_id like ?", (prefix + "%",)).fetchall()
    return {r[0] for r in rows}, {r[0] for r in rows if r[1] is not None}


def expected_keys(spec):
    """Keys for one listener: nft keys from global indexes, sequence keys from line numbers."""
    keys = set()
    for block in spec["blocks"]:
        if block["kind"] == "nft":
            base = NFT_PORT_BASE[block["track"]]
            for index in range(block["first"], block["first"] + block["count"]):
                keys.add("{}-n{}x{}".format(spec["listener"], base + index // 40000, 20000 + index % 40000))
        else:
            for index in range(block["first"], block["first"] + block["count"]):
                keys.add("{}-{}{:02d}x{:06d}".format(spec["listener"], block["sender"], block["scenario"], index))
    return keys


def parse_spec(args):
    """--blocks nft:TRACK:FIRST:COUNT or file:SENDER:SCENARIO:FIRST:COUNT, joined by '+'."""
    blocks = []
    for text in args.blocks.split("+"):
        parts = text.split(":")
        if parts[0] == "nft":
            blocks.append({"kind": "nft", "track": parts[1], "first": int(parts[2]), "count": int(parts[3])})
        else:
            blocks.append({"kind": "file", "sender": parts[1], "scenario": int(parts[2]), "first": int(parts[3]),
                           "count": int(parts[4])})
    return {"scenario": args.scenario,
            "listeners": [{"listener": listener, "blocks": blocks} for listener in args.listeners.split(",")]}


def measure(args):
    """Exact accounting at Bower queue acceptance for each listener in the scenario spec."""
    spec = parse_spec(args)
    deadline = time.time() + args.settle
    report = {"scenario": spec["scenario"], "measuredAt": None, "listeners": {}}
    while True:
        complete = True
        for listener in spec["listeners"]:
            expected = expected_keys(listener)
            accepted, delivered = queue_keys(listener["listener"] + "-")
            scoped = accepted & expected
            # Any accepted key for this listener that is not a well-formed probe key (for
            # example a key changed by a privacy detector) would hide a loss or a collision.
            pattern = re.compile(re.escape(listener["listener"]) + r"-(n\d{4}x\d{5}|[rg]\d{2}x\d{6})")
            malformed = {k for k in accepted if not pattern.fullmatch(k)}
            missing = sorted(expected - accepted)
            complete &= not missing
            report["listeners"][listener["listener"]] = {
                "expected": len(expected), "accepted": len(scoped), "missing": len(missing),
                "missingSample": missing[:20], "malformedKeys": len(malformed),
                "deliveredToSpool": len(delivered & expected),
                "missingSha256": hashlib.sha256("\n".join(missing).encode()).hexdigest()}
        if complete or time.time() >= deadline:
            break
        time.sleep(5)
    report["measuredAt"] = utc()
    report["syslog"] = status_summary()
    report["passed"] = all(v["missing"] == 0 and v["malformedKeys"] == 0 for v in report["listeners"].values())
    (RESULTS / ("measure-" + spec["scenario"] + ".json")).parent.mkdir(parents=True, exist_ok=True)
    (RESULTS / ("measure-" + spec["scenario"] + ".json")).write_text(json.dumps(report, indent=1))
    emit(report)


def collector_snapshot(args):
    queue = {}
    if QUEUE.exists():
        with sqlite3.connect("file:" + str(QUEUE) + "?mode=ro", uri=True, timeout=30) as db:
            queue = {"events": db.execute("select count(*) from queue_events").fetchone()[0],
                     "undelivered": db.execute("select count(*) from queue_events where delivered_at is null").fetchone()[0]}
    pid = sh("systemctl", "show", "bower", "--property=MainPID", "--value")
    usage = {}
    if pid not in ("", "0"):
        status_text = Path("/proc/" + pid + "/status").read_text()
        usage["rssKiB"] = int(re.search(r"VmRSS:\s+(\d+)", status_text).group(1))
        usage["hwmKiB"] = int(re.search(r"VmHWM:\s+(\d+)", status_text).group(1))
        stat = Path("/proc/" + pid + "/stat").read_text().split()
        usage["cpuSeconds"] = (int(stat[13]) + int(stat[14])) / os.sysconf("SC_CLK_TCK")
    emit({"at": utc(), "active": sh("systemctl", "is-active", "bower", check=False), "process": usage,
          "mainPid": sh("systemctl", "show", "bower", "--property=MainPID", "--value"),
          "restarts": sh("systemctl", "show", "bower", "--property=NRestarts", "--value"),
          "queue": queue, "syslog": status_summary(),
          "connections": sh("ss", "-tnoH", "state", "established", "( sport >= :6514 and sport <= :6516 )", check=False).count("\n") + 1
          if sh("ss", "-tnoH", "state", "established", "( sport >= :6514 and sport <= :6516 )", check=False) else 0})


# ---------------------------------------------------------------- faults

FAULT_TABLE = "bower_lab_fault"


def fault(args):
    """Scheduled fault on this host; prints measured timestamps."""
    wait_until(args.at)
    started = utc()
    detail = {}
    if args.action in ("blackhole", "reset"):
        if subprocess.run(["nft", "list", "table", "inet", FAULT_TABLE], capture_output=True).returncode == 0:
            raise RuntimeError("Fault table already present")
        verdict = "drop" if args.action == "blackhole" else "reject with tcp reset"
        rules = ("table inet {t} {{\n chain input {{\n  type filter hook input priority -10; policy accept;\n"
                 "  tcp dport 6514-6516 ip saddr {{ {s} }} counter {v}\n }}\n"
                 " chain output {{\n  type filter hook output priority -10; policy accept;\n"
                 "  tcp sport 6514-6516 ip daddr {{ {s} }} counter {o}\n }}\n}}").format(
            t=FAULT_TABLE, s=args.peers.replace(",", ", "), v=verdict, o="drop" if args.action == "blackhole" else "accept")
        Path(LAB / "fault.nft").write_text(rules + "\n")
        sh("nft", "-c", "-f", str(LAB / "fault.nft"))
        sh("nft", "-f", str(LAB / "fault.nft"))
        try:
            time.sleep(args.duration)
        finally:
            counters = sh("nft", "-j", "list", "table", "inet", FAULT_TABLE, check=False)
            sh("nft", "delete", "table", "inet", FAULT_TABLE)
        detail["packets"] = sum(e["counter"]["packets"] for item in json.loads(counters)["nftables"] if "rule" in item
                                for e in item["rule"]["expr"] if "counter" in e)
    elif args.action == "restart":
        sh("systemctl", "restart", args.unit)
    elif args.action == "stall":
        # Up but not reading: the process is frozen, the kernel keeps the connections open and
        # TCP flow control closes the window, as when Bower's queue is full.
        pid = int(sh("systemctl", "show", args.unit, "--property=MainPID", "--value"))
        os.kill(pid, 19)
        try:
            time.sleep(args.duration)
        finally:
            os.kill(pid, 18)
        detail["stalledPid"] = pid
    elif args.action == "kill":
        pid = sh("systemctl", "show", args.unit, "--property=MainPID", "--value")
        os.kill(int(pid), 9)
        detail["killedPid"] = int(pid)
    elif args.action == "stop-start":
        sh("systemctl", "stop", args.unit)
        time.sleep(args.duration)
        sh("systemctl", "start", args.unit)
    elif args.action == "journal-rotate":
        # journald file rotation makes imjournal reload its journal ("journal files changed").
        rotations = []
        end = time.monotonic() + args.duration
        while time.monotonic() < end:
            sh("journalctl", "--rotate")
            rotations.append(utc())
            time.sleep(min(args.interval, max(0, end - time.monotonic())))
        detail["rotations"] = rotations
    elif args.action == "docker-restart":
        sh("docker", "stop", "-t", "10", "bower-syslog-ng")
        time.sleep(args.duration)
        sh("docker", "start", "bower-syslog-ng")
    elif args.action == "reboot":
        (LAB / "reboot-requested").write_text(started + "\n")
        sh("systemctl", "reboot", check=False)
    else:
        raise RuntimeError("Unknown fault")
    emit({"fault": args.action, "startedAt": started, "endedAt": utc(), "duration": args.duration, **detail})


# ---------------------------------------------------------------- senders

NFT_TABLE = "bower_validation"


def netns_up(_args=None):
    """Disposable namespace whose packets to the host are logged and dropped by nftables."""
    if subprocess.run(["ip", "netns", "pid", NETNS], capture_output=True).returncode != 0 and \
            NETNS not in sh("ip", "netns", "list", check=False):
        sh("ip", "netns", "add", NETNS)
        sh("ip", "link", "add", "bwf0", "type", "veth", "peer", "name", "bwf1")
        sh("ip", "link", "set", "bwf1", "netns", NETNS)
        sh("ip", "addr", "add", "172.19.0.1/30", "dev", "bwf0")
        sh("ip", "link", "set", "bwf0", "up")
        sh("ip", "netns", "exec", NETNS, "ip", "addr", "add", "172.19.0.2/30", "dev", "bwf1")
        sh("ip", "netns", "exec", NETNS, "ip", "link", "set", "bwf1", "up")
        sh("ip", "netns", "exec", NETNS, "ip", "link", "set", "lo", "up")
    if subprocess.run(["nft", "list", "table", "inet", NFT_TABLE], capture_output=True).returncode != 0:
        rules = ("table inet {t} {{\n chain input {{\n  type filter hook input priority 0; policy accept;\n"
                 "  iifname \"bwf0\" udp dport 4400-4449 counter log prefix \"BOWER_DENY A \" drop\n"
                 "  iifname \"bwf0\" udp dport 4450-4499 counter log prefix \"BOWER_DENY B \" drop\n }}\n}}").format(t=NFT_TABLE)
        (LAB / "validation.nft").write_text(rules + "\n")
        sh("nft", "-c", "-f", str(LAB / "validation.nft"))
        sh("nft", "-f", str(LAB / "validation.nft"))


def nft_packets():
    """Packets matched by the track A and track B deny rules (in rule order)."""
    rules = json.loads(sh("nft", "-j", "list", "table", "inet", NFT_TABLE))
    counts = [e["counter"]["packets"] for item in rules["nftables"] if "rule" in item
              for e in item["rule"]["expr"] if "counter" in e]
    return dict(zip(("A", "B"), counts))


def install_sender(args):
    packages = ["rsyslog", "rsyslog-openssl", "nftables", "logrotate", "tcpdump"]
    if args.docker:
        packages.append("docker")
    sh("dnf", "-y", "-q", "install", *packages)
    unit = Path("/etc/systemd/system/bower-lab-netns.service")
    tool = Path("/opt/bower-lab/syslog-host.py")
    unit.write_text("[Unit]\nDescription=Bower lab nftables source namespace\nAfter=network-online.target\n"
                    "Before=rsyslog.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                    "ExecStart=/usr/bin/python3 " + str(tool) + " netns-up\n\n[Install]\nWantedBy=multi-user.target\n")
    sh("systemctl", "daemon-reload")
    sh("systemctl", "enable", "--now", "bower-lab-netns.service")
    SEQ_DIR.mkdir(parents=True, exist_ok=True)
    if args.docker:
        sh("systemctl", "enable", "--now", "docker")
    emit({"installed": sh("rpm", "-q", *packages), "netns": NETNS in sh("ip", "netns", "list"), "nft": nft_packets()})


RSYSLOG_ACTION = '''action(name="{name}" type="omfwd" target="{ip}" port="{port}" protocol="tcp"
       TCP_Framing="octet-counted" template="RSYSLOG_SyslogProtocol23Format"
       StreamDriver="ossl" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
       StreamDriverPermittedPeers="{peer}"{priority}
       RebindInterval="{rebind}" ResendLastMSGOnReconnect="{resend}"
       KeepAlive="{keepalive}" KeepAlive.Time="60" KeepAlive.Interval="10" KeepAlive.Probes="6"
       queue.type="LinkedList" queue.filename="bower_{name}" queue.saveOnShutdown="on"{queue}
       action.resumeRetryCount="-1" action.resumeInterval="5" action.reportSuspension="on")
'''
# Queue sizing per profile. "pilot" keeps rsyslog's defaults (1,000 messages in memory,
# timeoutEnqueue 2 s), as the pilot and ws6 did; "small" is the recommended profile scaled
# down so a short outage reaches the disk part.
RSYSLOG_QUEUES = {
    "recommended": '''
       queue.size="200000" queue.highWatermark="150000" queue.lowWatermark="100000"
       queue.maxDiskSpace="2g" queue.timeoutEnqueue="86400000" queue.discardMark="200000" queue.discardSeverity="8"
       queue.checkpointInterval="100" queue.syncQueueFiles="off"''',
    "small": '''
       queue.size="20000" queue.highWatermark="15000" queue.lowWatermark="10000"
       queue.maxDiskSpace="2g" queue.timeoutEnqueue="86400000" queue.discardMark="20000" queue.discardSeverity="8"
       queue.checkpointInterval="100" queue.syncQueueFiles="off"''',
    "pilot": "",
}


def configure_rsyslog(args):
    install_cert(args.cert)
    profile = args.profile
    tls12 = 'gnutlsPriorityString="MinProtocol=TLSv1.2\\nMaxProtocol=TLSv1.2"'
    lines = ["# Bower syslog delivery-reliability lab: profile " + profile,
             'global(DefaultNetstreamDriverCAFile="{0}/ca.pem" DefaultNetstreamDriverCertFile="{0}/{1}.pem"'
             ' DefaultNetstreamDriverKeyFile="{0}/{1}-key.pem")'.format(PKI, args.cert),
             'module(load="imfile" mode="inotify")',
             # A full queue blocks the input (the journal keeps events) instead of dropping
             # after rsyslog's default 2 s; the pilot profile keeps the defaults.
             '' if args.queue == "pilot" else 'main_queue(queue.timeoutEnqueue="86400000")',
             'module(load="impstats" interval="10" severity="7" log.syslog="off" log.file="/var/log/rsyslog-stats.log" format="json")']
    for name in ("create", "copytruncate", "idle"):
        lines.append('input(type="imfile" File="{d}/{n}.log" Tag="bowerseq" Ruleset="bower_{t}" freshStartTail="off"'
                     ' reopenOnTruncate="{r}" PersistStateInterval="1" addMetadata="off")'.format(
                         d=SEQ_DIR, n=name, t="b" if name == "idle" else "a", r="on" if name == "copytruncate" else "off"))
    tracks = {"a": [("a13", args.a, 6514, False), ("a12", args.a, 6516, True)],
              "b": [("b13i", args.b, 6514, False), ("b13n", args.b, 6515, False), ("b12i", args.b, 6516, True)]}
    if args.only:
        tracks = {t: [a for a in actions if a[0] in args.only.split(",")] for t, actions in tracks.items()}
    for track, actions in tracks.items():
        lines.append('ruleset(name="bower_{}") {{'.format(track))
        for name, ip, port, pin12 in actions:
            peer = "collector-" + track + "." + DOMAIN
            lines.append(RSYSLOG_ACTION.format(name=name, ip=ip, port=port, peer=peer, queue=RSYSLOG_QUEUES[args.queue],
                                               priority=("\n       " + tls12) if pin12 else "",
                                               rebind=args.rebind, resend="on" if profile == "recommended" else "off",
                                               keepalive="on" if profile == "recommended" else "off"))
        lines.append("}")
    lines.append('if $programname == "kernel" and $msg contains "BOWER_DENY A " then { call bower_a\n stop }')
    lines.append('if $programname == "kernel" and $msg contains "BOWER_DENY B " then { call bower_b\n stop }')
    Path("/etc/rsyslog.d/10-bower-lab.conf").write_text("\n".join(lines) + "\n")
    conf = Path("/etc/rsyslog.conf")
    text = conf.read_text()
    bounded = 'module(load="imjournal" StateFile="imjournal.state" Ratelimit.Interval="600" Ratelimit.Burst="200000")'
    if "Ratelimit.Burst" not in text:
        text = re.sub(r'module\(load="imjournal"[^)]*\)', bounded, text, count=1, flags=re.S)
        conf.write_text(text)
    check = subprocess.run(["rsyslogd", "-N1"], capture_output=True, text=True)
    if check.returncode != 0:
        print(check.stdout[-2000:], check.stderr[-2000:])
        raise RuntimeError("rsyslogd -N1 failed")
    sh("systemctl", "enable", "rsyslog")
    sh("systemctl", "restart", "rsyslog")
    emit({"profile": profile, "queue": args.queue, "rebind": args.rebind, "conf": hashlib.sha256(Path("/etc/rsyslog.d/10-bower-lab.conf").read_bytes()).hexdigest(),
          "rsyslogConf": hashlib.sha256(conf.read_bytes()).hexdigest(), "boundedImjournal": "Ratelimit.Burst" in conf.read_text(),
          "active": sh("systemctl", "is-active", "rsyslog", check=False)})


def generate(args):
    """Real kernel denials (nft) or sequence lines (file) at a fixed rate."""
    wait_until(args.at)
    started = time.monotonic()
    started_at = utc()
    sent = 0
    if args.kind == "nft":
        before = nft_packets()
        base = NFT_PORT_BASE[args.track]
        for i in range(args.count):
            index = args.first + i
            subprocess_payload = (base + index // 40000, 20000 + index % 40000)
            sock_send(subprocess_payload)
            sent += 1
            time.sleep(max(0, started + (i + 1) / args.rate - time.monotonic()))
        native = {k: v - before.get(k, 0) for k, v in nft_packets().items()}
    else:
        path = SEQ_DIR / (args.file + ".log")
        for i in range(args.count):
            # Reopen for every line, as a writer that reopens after rotation (postrotate
            # signal) does: a held descriptor keeps writing into the renamed file.
            with path.open("a") as stream:
                stream.write("BOWER_SEQ {}{:02d}x{:06d} synthetic delivery probe\n".format(args.sender, args.scenario, args.first + i))
            sent += 1
            time.sleep(max(0, started + (i + 1) / args.rate - time.monotonic()))
        native = None
    elapsed = time.monotonic() - started
    record = {"generator": args.kind, "track": args.track, "first": args.first, "count": args.count, "sent": sent,
              "rate": args.rate, "actualRate": sent / elapsed if elapsed else None, "startedAt": started_at,
              "endedAt": utc(), "nativeCounterDelta": native}
    (RESULTS / ("generate-" + args.label + ".json")).parent.mkdir(parents=True, exist_ok=True)
    (RESULTS / ("generate-" + args.label + ".json")).write_text(json.dumps(record))
    emit(record)


_NS_SOCKETS = {}


def sock_send(ports):
    """Send one UDP datagram from the namespace's address with a chosen source port."""
    dport, sport = ports
    if "helper" not in _NS_SOCKETS:
        _NS_SOCKETS["helper"] = subprocess.Popen(
            ["ip", "netns", "exec", NETNS, "python3", "-u", "-c",
             "import socket,sys\nfor line in sys.stdin:\n d,s=map(int,line.split())\n"
             " k=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
             " k.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
             " k.bind(('172.19.0.2',s)); k.sendto(b'bower-probe',('172.19.0.1',d)); k.close()\n"
             " print('ok',flush=True)\n"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    helper = _NS_SOCKETS["helper"]
    helper.stdin.write("{} {}\n".format(dport, sport))
    helper.stdin.flush()
    if helper.stdout.readline().strip() != "ok":
        raise RuntimeError("namespace sender failed")


def rotate(args):
    """logrotate in create or copytruncate mode while the generator writes."""
    wait_until(args.at)
    config = LAB / ("logrotate-" + args.mode + ".conf")
    config.write_text("{}/{}.log {{\n  rotate 20\n  missingok\n  notifempty\n  nocompress\n  {}\n}}\n".format(
        SEQ_DIR, args.mode, "copytruncate" if args.mode == "copytruncate" else "create 0640 root root"))
    times = []
    for i in range(args.times):
        sh("logrotate", "-f", "-s", str(LAB / "logrotate.state"), str(config))
        times.append(utc())
        if i + 1 < args.times:
            time.sleep(args.interval)
    emit({"rotated": args.mode, "times": times})


def sender_snapshot(args):
    stats = {}
    log = Path("/var/log/rsyslog-stats.log")
    if log.exists():
        for line in log.read_text().splitlines()[-400:]:
            try:
                item = json.loads(line[line.index("{"):])
            except ValueError:
                continue
            stats[item.get("name", "?") + "/" + item.get("origin", "?")] = {
                k: v for k, v in item.items() if k not in ("name", "origin")}
    queues = {p.name: p.stat().st_size for p in Path("/var/lib/rsyslog").glob("bower_*")} if Path("/var/lib/rsyslog").exists() else {}
    sockets = []
    for line in sh("ss", "-tnH", "state", "all", "( dport >= :6514 and dport <= :6516 )", check=False).splitlines():
        fields = line.split()
        if len(fields) >= 5:
            sockets.append({"state": fields[0], "recvQ": int(fields[1]), "sendQ": int(fields[2]),
                            "port": int(fields[4].rsplit(":", 1)[1])})
    diagnostics = {}
    for line in sh("journalctl", "-u", "rsyslog", "--since", args.since, "-o", "cat", "--no-pager", check=False).splitlines():
        key = re.sub(r"\d+", "N", line)[:160]
        diagnostics[key] = diagnostics.get(key, 0) + 1
    emit({"at": utc(), "rsyslog": sh("systemctl", "is-active", "rsyslog", check=False), "sockets": sockets,
          "rsyslogDiagnostics": dict(sorted(diagnostics.items(), key=lambda item: -item[1])[:15]),
          "nft": nft_packets() if NFT_TABLE in sh("nft", "list", "tables", check=False) else None,
          "impstats": {k: v for k, v in stats.items() if k.startswith(("a1", "b1", "imjournal", "imfile", "main Q", "action-"))
                       or "bower" in k},
          "queueFiles": queues, "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip()})


def journal_count(args):
    """Kernel denial lines journald recorded in a window (native source evidence)."""
    out = sh("journalctl", "-k", "--since", args.since, "--until", args.until, "-o", "cat", "--no-pager", check=False)
    count = sum(1 for line in out.splitlines() if ("BOWER_DENY " + args.track + " ") in line)
    emit({"journalKernelLines": count, "track": args.track, "since": args.since, "until": args.until})


def peek(raw):
    """rsyslog's CheckConnection: a non-blocking one-byte MSG_PEEK on the TCP socket."""
    try:
        data = raw.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
    except BlockingIOError:
        return "nothing-pending"
    except OSError as error:
        return "error:" + (error.strerror or str(error.errno))
    return "end-of-stream" if not data else "bytes-pending"


def peek_probe(args):
    """Connects like an rsyslog TLS sender that never reads, then peeks as rsyslog does before each send."""
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(str(PKI / "ca.pem"))
    context.load_cert_chain(str(PKI / (args.cert + ".pem")), str(PKI / (args.cert + "-key.pem")))
    version = ssl.TLSVersion.TLSv1_3 if args.tls == "1.3" else ssl.TLSVersion.TLSv1_2
    context.minimum_version = context.maximum_version = version
    plain = socket.create_connection((args.ip, args.port), timeout=10)
    secure = context.wrap_socket(plain, server_hostname=args.peer)
    raw = socket.socket(fileno=os.dup(secure.fileno()))
    time.sleep(1)
    after_handshake = peek(raw)
    pending = len(raw.recv(65536, socket.MSG_PEEK | socket.MSG_DONTWAIT)) if after_handshake == "bytes-pending" else 0
    observations = [{"at": 1, "peek": after_handshake, "bytesPending": pending}]
    for second in [int(x) for x in args.checks.split(",") if x]:
        time.sleep(max(0, second - observations[-1]["at"]))
        observations.append({"at": second, "peek": peek(raw), "tcpState": tcp_state(raw)})
    raw.close()
    secure.close()
    emit({"probe": "peek", "tls": secure.version() if False else args.tls, "negotiated": args.tls,
          "port": args.port, "observations": observations})


def tcp_state(raw):
    """Kernel TCP state of the socket (1 established, 8 close-wait)."""
    import struct
    info = raw.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 8)
    return {1: "established", 8: "close-wait", 7: "close"}.get(struct.unpack("B", info[:1])[0], str(info[0]))


def result(args):
    """Print a stored result file (metadata only)."""
    path = RESULTS / (args.label + ".json")
    emit(json.loads(path.read_text()) if path.exists() else {"missing": args.label})


SYSLOG_NG_IMAGE = "balabit/syslog-ng@sha256:73a81e8a700df1f5ee308218b01b8c8a0bd7026321940f3c20e389b9ca3c0b12"
SYSLOG_NG_DESTINATION = """destination d_{name} {{
  syslog("{ip}" port({port}) transport("tls")
    tls(ca-file("{pki}/ca.pem") cert-file("{pki}/{cert}.pem") key-file("{pki}/{cert}-key.pem")
        peer-verify(required-trusted){options})
    so-keepalive(yes) time-reopen(5)
    disk-buffer(reliable(yes) dir("/var/lib/syslog-ng") disk-buf-size(1073741824) mem-buf-size(16777216)));
}};
"""


def configure_syslogng(args):
    """syslog-ng in the official container: file sources, RFC 5425 TLS, reliable disk buffer."""
    install_cert(args.cert)
    config_dir = Path("/etc/bower-lab")
    config_dir.mkdir(parents=True, exist_ok=True)
    (LAB / "syslog-ng").mkdir(parents=True, exist_ok=True)
    SEQ_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("create", "copytruncate", "idle"):
        (SEQ_DIR / (name + ".log")).touch()
    lines = ["@version: current", '@include "scl.conf"',
             "options { keep-hostname(no); chain-hostnames(no); stats(freq(10)); log-fifo-size(20000); };",
             'log { source { internal(); }; destination { file("/dev/stdout"); }; };']
    for track, files in (("a", ("create", "copytruncate")), ("b", ("idle",))):
        lines.append("source s_{} {{".format(track))
        for name in files:
            lines.append('  file("{}/{}.log" program-override("bowerseq") flags(no-parse) follow-freq(1));'.format(SEQ_DIR, name))
        lines.append("};")
    targets = {"a": [("a13", args.a, 6514, ""), ("a12", args.a, 6516, " ssl-options(no-sslv2, no-sslv3, no-tlsv1, no-tlsv11, no-tlsv13)")],
               "b": [("b13i", args.b, 6514, ""), ("b13n", args.b, 6515, ""),
                     ("b12i", args.b, 6516, " ssl-options(no-sslv2, no-sslv3, no-tlsv1, no-tlsv11, no-tlsv13)")]}
    for track, destinations in targets.items():
        for name, ip, port, options in destinations:
            lines.append(SYSLOG_NG_DESTINATION.format(name=name, ip=ip, port=port, pki=PKI, cert=args.cert, options=options))
            lines.append("log {{ source(s_{}); destination(d_{}); }};".format(track, name))
    config = config_dir / "syslog-ng.conf"
    config.write_text("\n".join(lines) + "\n")
    sh("docker", "pull", "-q", SYSLOG_NG_IMAGE)
    image = sh("docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", SYSLOG_NG_IMAGE)
    sh("docker", "rm", "-f", "bower-syslog-ng", check=False)
    check = subprocess.run(["docker", "run", "--rm", "-v", str(config) + ":/etc/syslog-ng/syslog-ng.conf:ro",
                            "-v", str(PKI) + ":" + str(PKI) + ":ro", SYSLOG_NG_IMAGE, "--syntax-only"],
                           capture_output=True, text=True)
    if check.returncode != 0:
        print(check.stdout[-2000:], check.stderr[-2000:])
        raise RuntimeError("syslog-ng --syntax-only failed")
    sh("docker", "run", "-d", "--name", "bower-syslog-ng", "--network", "host", "--restart", "unless-stopped",
       "-v", str(config) + ":/etc/syslog-ng/syslog-ng.conf:ro", "-v", str(PKI) + ":" + str(PKI) + ":ro",
       "-v", str(SEQ_DIR) + ":" + str(SEQ_DIR) + ":ro", "-v", str(LAB / "syslog-ng") + ":/var/lib/syslog-ng",
       SYSLOG_NG_IMAGE, "--no-caps")
    time.sleep(5)
    version = sh("docker", "exec", "bower-syslog-ng", "syslog-ng", "--version").splitlines()[0]
    emit({"syslogNg": image, "version": version, "conf": hashlib.sha256(config.read_bytes()).hexdigest(),
          "running": sh("docker", "inspect", "--format", "{{.State.Status}}", "bower-syslog-ng"),
          "log": [l for l in sh("docker", "logs", "--tail", "20", "bower-syslog-ng", check=False).splitlines()][-10:]})


def syslogng_snapshot(args):
    logs = sh("docker", "logs", "--since", args.since, "bower-syslog-ng", check=False)
    merged = subprocess.run(["docker", "logs", "--since", args.since, "bower-syslog-ng"], capture_output=True, text=True)
    diagnostics = {}
    for line in (merged.stdout + merged.stderr).splitlines():
        if re.match(r"^[A-Z_][A-Z0-9_]*=", line) or not line.strip():
            continue
        key = re.sub(r"\d+", "N", re.sub(r"^\S+ \S+ ", "", line).split(";", 1)[0])[:160]
        diagnostics[key] = diagnostics.get(key, 0) + 1
    stats = subprocess.run(["docker", "exec", "bower-syslog-ng", "syslog-ng-ctl", "stats"], capture_output=True, text=True).stdout
    keep = [l for l in stats.splitlines() if "d_" in l and any(t in l for t in ("dropped", "processed", "queued", "written"))]
    buffers = {p.name: p.stat().st_size for p in (LAB / "syslog-ng").glob("*.qf")}
    emit({"at": utc(), "diagnostics": dict(sorted(diagnostics.items(), key=lambda i: -i[1])[:15]), "stats": keep,
          "diskBuffers": buffers, "logsBytes": len(logs)})


def collector_tickets(args):
    """Bower-only OpenSSL configuration: the system file plus NumTickets = 0 (no TLS 1.3 tickets)."""
    dropin = Path("/etc/systemd/system/bower.service.d/openssl.conf")
    config = Path("/etc/bower/openssl.cnf")
    if args.mode == "disable":
        system = Path("/etc/pki/tls/openssl.cnf").read_text()
        section = re.search(r"^\s*system_default\s*=\s*(\S+)", system, re.M).group(1)
        updated, count = re.subn(r"(^\[\s*" + re.escape(section) + r"\s*\][^\n]*\n)", r"\1NumTickets = 0\n", system, count=1, flags=re.M)
        if count != 1:
            raise RuntimeError("system_default section not found")
        config.write_text(updated)
        os.chmod(config, 0o644)
        dropin.parent.mkdir(parents=True, exist_ok=True)
        dropin.write_text("[Service]\nEnvironment=OPENSSL_CONF=" + str(config) + "\n")
    else:
        dropin.unlink(missing_ok=True)
        config.unlink(missing_ok=True)
    sh("systemctl", "daemon-reload")
    sh("systemctl", "restart", "bower")
    time.sleep(3)
    emit({"tickets": args.mode, "dropIn": dropin.exists(), "active": sh("systemctl", "is-active", "bower", check=False),
          "configSha256": hashlib.sha256(config.read_bytes()).hexdigest() if config.exists() else None})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("csr"); p.add_argument("--name", required=True); p.set_defaults(func=csr)
    p = sub.add_parser("ca"); p.set_defaults(func=ca)
    p = sub.add_parser("sign"); p.add_argument("--names", required=True); p.set_defaults(func=sign)
    p = sub.add_parser("install-collector"); p.add_argument("--rpm", required=True); p.add_argument("--sha256", required=True)
    p.set_defaults(func=install_collector)
    p = sub.add_parser("build-pack"); p.add_argument("--source", required=True); p.add_argument("--sha256", required=True); p.set_defaults(func=build_pack)
    p = sub.add_parser("configure-collector"); p.add_argument("--listeners", required=True); p.add_argument("--senders", required=True)
    p.add_argument("--idle", type=int); p.set_defaults(func=configure_collector)
    p = sub.add_parser("snapshot"); p.set_defaults(func=collector_snapshot)
    p = sub.add_parser("measure"); p.add_argument("--scenario", required=True); p.add_argument("--listeners", required=True)
    p.add_argument("--blocks", required=True); p.add_argument("--settle", type=int, default=120)
    p.set_defaults(func=measure)
    p = sub.add_parser("fault"); p.add_argument("--action", required=True); p.add_argument("--at", type=float, required=True)
    p.add_argument("--duration", type=int, default=0); p.add_argument("--unit", default="bower"); p.add_argument("--peers", default="")
    p.add_argument("--interval", type=int, default=10)
    p.set_defaults(func=fault)
    p = sub.add_parser("netns-up"); p.set_defaults(func=netns_up)
    p = sub.add_parser("install-sender"); p.add_argument("--docker", action="store_true"); p.set_defaults(func=install_sender)
    p = sub.add_parser("configure-rsyslog"); p.add_argument("--a", required=True); p.add_argument("--b", required=True)
    p.add_argument("--cert", required=True); p.add_argument("--profile", choices=("recommended", "pilot"), default="recommended")
    p.add_argument("--rebind", type=int, default=0); p.add_argument("--only")
    p.add_argument("--queue", choices=tuple(RSYSLOG_QUEUES), default="recommended"); p.set_defaults(func=configure_rsyslog)
    p = sub.add_parser("generate"); p.add_argument("--kind", choices=("nft", "file"), required=True)
    p.add_argument("--track", choices=("A", "B"), default="A"); p.add_argument("--first", type=int, required=True)
    p.add_argument("--count", type=int, required=True); p.add_argument("--rate", type=float, required=True)
    p.add_argument("--at", type=float, required=True); p.add_argument("--file", default="create")
    p.add_argument("--sender", default="r"); p.add_argument("--scenario", type=int, default=0); p.add_argument("--label", required=True)
    p.set_defaults(func=generate)
    p = sub.add_parser("rotate"); p.add_argument("--mode", choices=("create", "copytruncate"), required=True)
    p.add_argument("--at", type=float, required=True); p.add_argument("--times", type=int, default=3)
    p.add_argument("--interval", type=int, default=30); p.set_defaults(func=rotate)
    p = sub.add_parser("sender-snapshot"); p.add_argument("--since", default="-15min"); p.set_defaults(func=sender_snapshot)
    p = sub.add_parser("peek-probe"); p.add_argument("--ip", required=True); p.add_argument("--port", type=int, required=True)
    p.add_argument("--peer", required=True); p.add_argument("--cert", required=True); p.add_argument("--tls", choices=("1.2", "1.3"), required=True)
    p.add_argument("--checks", default="5"); p.set_defaults(func=peek_probe)
    p = sub.add_parser("configure-syslogng"); p.add_argument("--a", required=True); p.add_argument("--b", required=True)
    p.add_argument("--cert", required=True); p.set_defaults(func=configure_syslogng)
    p = sub.add_parser("syslogng-snapshot"); p.add_argument("--since", default="15m"); p.set_defaults(func=syslogng_snapshot)
    p = sub.add_parser("collector-tickets"); p.add_argument("--mode", choices=("disable", "enable"), required=True)
    p.set_defaults(func=collector_tickets)
    p = sub.add_parser("result"); p.add_argument("--label", required=True); p.set_defaults(func=result)
    p = sub.add_parser("journal-count"); p.add_argument("--since", required=True); p.add_argument("--until", required=True)
    p.add_argument("--track", default="A"); p.set_defaults(func=journal_count)
    args = parser.parse_args()
    if args.command != "netns-up":
        require_lab()
    args.func(args)


if __name__ == "__main__":
    main()
