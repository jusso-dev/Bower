#!/usr/bin/env python3
"""Storage-pressure scenarios on the disposable Linux collector (run as root).

A sequence-numbered generator feeds a local rsyslog sender (disk-assisted queue,
mutual TLS to Bower). The driver blocks only the collector's HTTPS (by service UID),
fills the dedicated queue volume with a bounded filler file, restarts the service
and samples metadata every five seconds. Output is metadata only: counters, sizes,
states, times and identity digests; never payloads, keys or tokens.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

QUEUE_DIR = Path("/var/lib/bower")
FILLER = QUEUE_DIR / "ws3-filler"
STATE = Path("/var/lib/ws3-lab")
LOGS = Path("/var/log/ws3")
TOKEN = Path("/etc/bower/secrets/ingest-token")
MIB = 1024 * 1024


def now():
    return dt.datetime.now(dt.timezone.utc)


def iso(value=None):
    return (value or now()).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def status():
    request = urllib.request.Request("http://127.0.0.1:4319/v1/status",
                                     headers={"Authorization": "Bearer " + TOKEN.read_text().strip()})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read(4 * MIB))


def healthy():
    try:
        with urllib.request.urlopen("http://127.0.0.1:4319/health", timeout=5) as response:
            return json.loads(response.read(4096)).get("status")
    except Exception:  # noqa: BLE001 - down is a valid observation
        return None


def volume():
    stats = os.statvfs(QUEUE_DIR)
    return stats.f_bavail * stats.f_frsize, stats.f_blocks * stats.f_frsize


def rsyslog():
    """Latest impstats values for the Bower forwarding action and its queue."""
    path = LOGS / "rsyslog-stats.json"
    if not path.exists():
        return {}
    with path.open("rb") as stream:
        stream.seek(max(0, path.stat().st_size - 256 * 1024))
        lines = stream.read().decode("utf-8", "replace").splitlines()[1:]
    found = {}
    for line in lines:
        start = line.find("{")
        if start < 0:
            continue
        try:
            item = json.loads(line[start:])
        except ValueError:
            continue
        name = item.get("name", "")
        if name in ("bower queue", "bower queue[DA]", "bower", "imtcp(127.0.0.1:5514)", "ws3"):
            found[name] = {key: item[key] for key in ("size", "maxqsize", "enqueued", "discarded.full",
                           "discarded.nf", "full", "processed", "failed", "suspended", "submitted", "resumed")
                           if key in item}
    return found


def sender_queue(stats):
    return sum(stats.get(name, {}).get("size", 0) for name in ("bower queue", "bower queue[DA]"))


def block():
    rule = ("table inet ws3_block { chain out { type filter hook output priority 0; policy accept; "
            "meta skuid \"bower\" tcp dport 443 reject with tcp reset; } }")
    subprocess.run(["nft", "-f", "-"], input=rule, text=True, check=True)


def unblock():
    subprocess.run(["nft", "delete", "table", "inet", "ws3_block"], capture_output=True)


def blocked():
    return subprocess.run(["nft", "list", "table", "inet", "ws3_block"], capture_output=True).returncode == 0


def fill_to(free_target):
    """Grows or shrinks the filler so that free space is about free_target bytes."""
    free, _ = volume()
    current = FILLER.stat().st_size if FILLER.exists() else 0
    size = max(0, current + free - free_target)
    if size == 0:
        FILLER.unlink(missing_ok=True)
        return 0
    if size < current:
        os.truncate(FILLER, size)
    else:
        subprocess.run(["fallocate", "-l", str(size), str(FILLER)], check=True)
    return size


def fill_completely():
    """Allocates every remaining block, then writes until ENOSPC."""
    free, _ = volume()
    if free > 8 * MIB:
        fill_to(4 * MIB)
    chunk = b"\0" * 65536
    with FILLER.open("ab") as stream:
        for size in (65536, 4096, 512):
            try:
                while True:
                    stream.write(chunk[:size])
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError:
                pass
    return FILLER.stat().st_size


def release_filler():
    FILLER.unlink(missing_ok=True)


class Generator(threading.Thread):
    """Sends ws3lNNNNNNN sequence numbers to rsyslog at a fixed rate, persisting the next one."""

    def __init__(self, rate):
        super().__init__(daemon=True)
        self.rate = rate
        self.stopping = threading.Event()
        STATE.mkdir(parents=True, exist_ok=True)
        self.next_file = STATE / "next-seq"
        self.next = int(self.next_file.read_text()) if self.next_file.exists() else 1
        self.first = self.next
        self.blocked_seconds = 0.0

    def run(self):
        connection = socket.create_connection(("127.0.0.1", 5514))
        started = time.monotonic()
        sent = 0
        try:
            while not self.stopping.is_set():
                due = started + sent / self.rate
                delay = due - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                else:
                    self.blocked_seconds = max(self.blocked_seconds, -delay)
                seq = self.next
                line = (f"<134>1 {iso()} ws3-linux bowerseq - - - "
                        f"BOWER_SEQ seq=ws3l{seq:07d} src=192.0.2.{seq % 250 + 1}\n")
                connection.sendall(line.encode())
                self.next = seq + 1
                sent += 1
                if sent % 50 == 0:
                    self.next_file.write_text(str(self.next))
        finally:
            connection.close()
            self.next_file.write_text(str(self.next))

    def stop(self):
        self.stopping.set()
        self.join(30)


class Recorder:
    def __init__(self, scenario):
        LOGS.mkdir(parents=True, exist_ok=True)
        self.path = LOGS / f"{scenario}.jsonl"
        self.events = []
        self.samples = []
        self.generator = None
        self.phase = "start"
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def mark(self, name, **values):
        record = {"at": iso(), "event": name, **values}
        self.events.append(record)
        with self.path.open("a") as stream:
            stream.write(json.dumps({"kind": "event", **record}) + "\n")
        self.phase = name

    def sample(self):
        free, total = volume()
        row = {"at": iso(), "phase": self.phase, "freeBytes": free, "totalBytes": total,
               "fillerBytes": FILLER.stat().st_size if FILLER.exists() else 0,
               "destinationBlocked": blocked(), "health": healthy(),
               "generatorNext": self.generator.next if self.generator else None}
        try:
            s = status()
            storage = s.get("storage") or {}
            listener = (s.get("syslog") or [{}])[0]
            queue = s.get("queue") or {}
            row.update({
                "storageState": storage.get("state"), "intakePaused": storage.get("intakePaused"),
                "queueFileBytes": storage.get("queueFileBytes"), "pageUtilisation": storage.get("queuePageUtilisationPercent"),
                "queueUtilisation": storage.get("queueUtilisationPercent"), "oldestPendingAge": storage.get("oldestPendingAgeSeconds"),
                "storageRefusals": storage.get("storageRefusals"), "pressurePurged": storage.get("pressurePurgedEvents"),
                "capacityRefusals": (s.get("intake") or {}).get("capacityRefusals"),
                "queued": queue.get("queued"), "uploading": queue.get("uploading"), "retrying": queue.get("retrying"),
                "delivered": queue.get("delivered"), "deadLettered": queue.get("deadLettered"),
                "undeliveredBytes": queue.get("undeliveredBytes"),
                "listenerQueued": listener.get("queued"), "listenerRetries": listener.get("retries"),
                "listenerSubmitFailures": listener.get("submitFailures"), "listenerDropped": listener.get("dropped"),
                "listenerConnections": listener.get("activeConnections")})
        except Exception as error:  # noqa: BLE001 - collector down is a valid observation
            row["statusError"] = type(error).__name__
        stats = rsyslog()
        row["senderQueue"] = sender_queue(stats)
        row["senderDiscarded"] = sum(item.get("discarded.full", 0) + item.get("discarded.nf", 0) for item in stats.values())
        self.samples.append(row)
        with self.path.open("a") as stream:
            stream.write(json.dumps({"kind": "sample", **row}) + "\n")
        return row

    def loop(self):
        while not self.stopping.wait(5):
            try:
                self.sample()
            except Exception as error:  # noqa: BLE001
                self.mark("sample-error", error=type(error).__name__)

    def wait(self, condition, timeout, label):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = self.samples[-1] if self.samples else self.sample()
            if condition(row):
                self.mark(label, met=True)
                return row
            time.sleep(2)
        self.mark(label, met=False)
        return None


def drained(row):
    return (row.get("queued") == 0 and row.get("uploading") == 0 and row.get("retrying") == 0
            and row.get("senderQueue") == 0 and row.get("intakePaused") is False)


def journal_counts(since):
    output = subprocess.run(["journalctl", "-u", "bower", "--since", since, "-o", "cat", "--no-pager"],
                            capture_output=True, text=True).stdout.splitlines()
    counts = {}
    for line in output:
        match = re.search(r"([A-Za-z.]+)\[(\d+)\]", line)
        key = f"{match.group(1)}[{match.group(2)}]" if match else "other"
        counts[key] = counts.get(key, 0) + 1
    return {"lines": len(output), "bytes": sum(len(line) + 1 for line in output), "byEvent": counts}


def summarise(recorder, started, generator):
    rows = recorder.samples
    def first(predicate):
        return next((row["at"] for row in rows if predicate(row)), None)
    return {
        "startedAt": started, "endedAt": iso(), "events": recorder.events,
        "generated": {"firstSeq": generator.first, "nextSeq": generator.next, "count": generator.next - generator.first,
                      "rate": generator.rate, "maximumSendLagSeconds": round(generator.blocked_seconds, 3)},
        "firstWarningAt": first(lambda row: row.get("storageState") in ("warning", "critical")),
        "firstCriticalAt": first(lambda row: row.get("storageState") == "critical"),
        "firstRefusalAt": first(lambda row: (row.get("listenerRetries") or 0) > (rows[0].get("listenerRetries") or 0)),
        "maximumSenderQueue": max((row.get("senderQueue") or 0) for row in rows) if rows else None,
        "maximumUndeliveredBytes": max((row.get("undeliveredBytes") or 0) for row in rows) if rows else None,
        "minimumFreeBytes": min(row["freeBytes"] for row in rows) if rows else None,
        "maximumQueueFileBytes": max((row.get("queueFileBytes") or 0) for row in rows) if rows else None,
        "senderDiscarded": rows[-1].get("senderDiscarded") if rows else None,
        "listenerSubmitFailures": rows[-1].get("listenerSubmitFailures") if rows else None,
        "listenerDropped": rows[-1].get("listenerDropped") if rows else None,
        "samples": len(rows), "final": rows[-1] if rows else None,
        "journal": journal_counts(started.replace("T", " ").rstrip("Z")),
    }


def scenario_queue_cap(recorder, generator, args):
    recorder.mark("generating", rate=generator.rate)
    time.sleep(30)
    block()
    recorder.mark("destination-blocked")
    refused = recorder.wait(lambda row: (row.get("listenerRetries") or 0) > 0 and (row.get("capacityRefusals") or 0) > 0,
                            args.limit, "queue-cap-refusing")
    if refused:
        time.sleep(args.hold)
        recorder.sample()
    unblock()
    recorder.mark("destination-restored")
    time.sleep(120)


def scenario_watermarks(recorder, generator, args):
    recorder.mark("generating", rate=generator.rate)
    time.sleep(20)
    block()
    recorder.mark("destination-blocked")
    s = status()["storage"]
    fill_to(s["warningFreeBytes"] - 32 * MIB)
    recorder.mark("filled-below-warning", fillerBytes=FILLER.stat().st_size)
    recorder.wait(lambda row: row.get("storageState") == "warning", 60, "warning-reported")
    time.sleep(60)
    fill_to(s["criticalFreeBytes"] + 24 * MIB)
    recorder.mark("filled-near-critical", fillerBytes=FILLER.stat().st_size)
    recorder.wait(lambda row: row.get("storageState") == "critical", args.limit, "critical-reported")
    time.sleep(args.hold)
    release_filler()
    recorder.mark("space-freed")
    recorder.wait(lambda row: row.get("storageState") == "normal" and row.get("intakePaused") is False, 120, "intake-resumed")
    time.sleep(60)
    unblock()
    recorder.mark("destination-restored")
    time.sleep(60)


def scenario_disk_full(recorder, generator, args):
    recorder.mark("generating", rate=generator.rate)
    time.sleep(20)
    block()
    recorder.mark("destination-blocked")
    time.sleep(30)
    size = fill_completely()
    recorder.mark("volume-full", fillerBytes=size, freeBytes=volume()[0])
    recorder.wait(lambda row: row.get("storageState") == "critical", 60, "critical-reported")
    unblock()
    recorder.mark("destination-restored-while-full")
    time.sleep(args.hold)
    restart = iso()
    subprocess.run(["systemctl", "restart", "bower"], check=False)
    recorder.mark("service-restarted-while-full")
    up = recorder.wait(lambda row: row.get("health") is not None, 180, "service-answering-while-full")
    recorder.mark("restart-observation", answered=up is not None, journal=journal_counts(restart.replace("T", " ").rstrip("Z")),
                  activeState=subprocess.run(["systemctl", "is-active", "bower"], capture_output=True, text=True).stdout.strip(),
                  restarts=subprocess.run(["systemctl", "show", "bower", "-p", "NRestarts", "--value"],
                                          capture_output=True, text=True).stdout.strip())
    time.sleep(60)
    release_filler()
    recorder.mark("space-freed")
    recorder.wait(lambda row: row.get("health") is not None and row.get("intakePaused") is False, 300, "intake-resumed")
    time.sleep(60)


def reconcile():
    """Generated sequence numbers against queued identities (read-only)."""
    generated_next = int((STATE / "next-seq").read_text())
    expected = {f"ws3l{seq:07d}" for seq in range(1, generated_next)}
    connection = sqlite3.connect(f"file:{QUEUE_DIR / 'queue.db'}?mode=ro", uri=True)
    seen, delivered, duplicates, payload_bytes, rows = {}, set(), 0, 0, 0
    for event_id, payload, state, size in connection.execute(
            "SELECT event_id, payload, state, payload_bytes FROM queue_events_v5"):
        rows += 1
        payload_bytes += size
        envelope = json.loads(payload)
        sequence = ((envelope.get("request") or {}).get("correlationId"))
        if not sequence:
            continue
        if sequence in seen:
            duplicates += 1
        seen[sequence] = event_id
        if state == 3:
            delivered.add(sequence)
    purged = connection.execute("SELECT COUNT(*) FROM queue_ledger WHERE purged_at IS NOT NULL").fetchone()[0] \
        if connection.execute("SELECT COUNT(*) FROM pragma_table_info('queue_ledger') WHERE name='purged_at'").fetchone()[0] else None
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    connection.close()
    digest = lambda values: hashlib.sha256("\n".join(sorted(values)).encode()).hexdigest()
    missing = sorted(expected - set(seen))
    return {"generated": len(expected), "queuedIdentities": len(seen), "missingFromQueue": len(missing),
            "missingSample": missing[:20], "unexpected": len(set(seen) - expected), "duplicateSequences": duplicates,
            "deliveredInQueue": len(delivered), "queueRows": rows, "averagePayloadBytes": payload_bytes // max(rows, 1),
            "generatedDigest": digest(expected), "queuedDigest": digest(seen), "sqliteIntegrity": integrity,
            "ledgerPurgedRows": purged, "rsyslog": rsyslog()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["queue-cap", "watermarks", "disk-full", "reconcile", "probe"])
    parser.add_argument("--rate", type=int, default=100)
    parser.add_argument("--hold", type=int, default=120)
    parser.add_argument("--limit", type=int, default=3600)
    parser.add_argument("--drain", type=int, default=1800)
    args = parser.parse_args()
    if args.scenario == "reconcile":
        print(json.dumps({"phase": "linux-reconcile", "at": iso(), **reconcile()}))
        return
    recorder = Recorder(args.scenario)
    if args.scenario == "probe":
        print(json.dumps({"phase": "probe", **recorder.sample()}))
        return
    started = iso()
    generator = Generator(args.rate)
    recorder.generator = generator
    recorder.sample()
    recorder.thread.start()
    generator.start()
    try:
        {"queue-cap": scenario_queue_cap, "watermarks": scenario_watermarks,
         "disk-full": scenario_disk_full}[args.scenario](recorder, generator, args)
    finally:
        generator.stop()
        recorder.mark("generator-stopped", nextSeq=generator.next)
        unblock()
        release_filler()
    recorder.wait(drained, args.drain, "drained")
    recorder.stopping.set()
    recorder.sample()
    summary = {"phase": f"linux-{args.scenario}", **summarise(recorder, started, generator)}
    (LOGS / f"{args.scenario}-summary.json").write_text(json.dumps(summary))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
