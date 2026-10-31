#!/usr/bin/env python3
"""Local Bower collector health check for Linux hosts (Python 3.9+ standard library only).

Reads the collector's /health and token-protected /v1/status on the local listener, plus
free space on the queue volume, and reports one verdict:

  exit 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN (Nagios/Icinga/Zabbix convention)

Output formats: a one-line summary (default), JSON (--format json) or Prometheus text
(--format prometheus, or --prometheus-file for the node_exporter textfile collector).
Metadata only: never prints the token, payloads, event ids or endpoints.
"""

import argparse
import json
import re
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}
SYSLOG_ERRORS = ("connectionsRejected", "sendersDenied", "tlsHandshakeFailures", "malformed", "oversized",
                 "framingErrors", "timeouts", "dropped", "submitFailures", "receiveErrors", "parserErrors")
WINDOWS_ERRORS = ("readErrors", "gaps", "resets", "submitFailures", "parserErrors", "cursorConflicts")
MAX_BODY = 4 * 1024 * 1024


def parser():
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument("--url", default=os.environ.get("BOWER_HEALTHCHECK_URL", "http://127.0.0.1:4319"),
                        help="Collector listener (default %(default)s)")
    result.add_argument("--token-file", default=os.environ.get("BOWER_HEALTHCHECK_TOKEN_FILE"),
                        help="File holding the collector ingest token; without it only /health is checked")
    result.add_argument("--queue-path", default=os.environ.get("BOWER_QUEUE_PATH", "/var/lib/bower/queue.db"),
                        help="Queue database; its volume is checked for free space")
    result.add_argument("--queue-max-bytes", type=int,
                        default=int(os.environ.get("BOWER_QUEUE_MAX_BYTES", str(10 * 1024 ** 3))),
                        help="The collector's BOWER_QUEUE_MAX_BYTES (default 10 GiB)")
    result.add_argument("--backlog-warning-seconds", type=int, default=900)
    result.add_argument("--backlog-critical-seconds", type=int, default=3600)
    result.add_argument("--storage-warning-percent", type=float, default=40.0,
                        help="Undelivered bytes as a percentage of BOWER_QUEUE_MAX_BYTES")
    result.add_argument("--storage-critical-percent", type=float, default=60.0)
    result.add_argument("--file-warning-percent", type=float, default=70.0,
                        help="Queue database size as a percentage of its page limit")
    result.add_argument("--file-critical-percent", type=float, default=85.0)
    result.add_argument("--disk-warning-percent", type=float, default=20.0, help="Free space below which to warn")
    result.add_argument("--disk-critical-percent", type=float, default=10.0)
    result.add_argument("--refusal-window-seconds", type=int, default=900,
                        help="A capacity refusal this recent is critical")
    result.add_argument("--state-file", help="Remember counters between runs to report new syslog/WEC errors")
    result.add_argument("--churn-warning-connections", type=int, default=5,
                        help="New syslog connections per run above which a listener reports churn")
    result.add_argument("--timeout", type=float, default=5.0)
    result.add_argument("--format", choices=("text", "json", "prometheus"), default="text")
    result.add_argument("--prometheus-file", help="Also write Prometheus text here atomically")
    return result


def fetch(url, token, timeout):
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    if token:
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-supplied local URL
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("response-too-large")
        return json.loads(body)


def parse_time(value):
    """Parses ISO 8601 with any fractional precision (.NET writes seven digits)."""
    if not value:
        return None
    match = re.fullmatch(r"(.+?)(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?", value)
    if match is None:
        raise ValueError("invalid-time")
    head, fraction, offset = match.groups()
    text = head + ("." + fraction[:6].ljust(6, "0") if fraction else "") + ("+00:00" if offset in (None, "Z") else offset)
    return datetime.fromisoformat(text)


def read_token(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as source:
        token = source.read().strip()
    return token or None


def load_state(path):
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as source:
            return json.load(source)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    if not path:
        return
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".bower-healthcheck-")
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(state, target)
    os.replace(temporary, path)


def queue_file_limit(queue_max_bytes):
    """The collector's SQLite page limit for the queue database: (4 x cap + 16 MiB) / 4."""
    return (queue_max_bytes * 4 + 16 * 1024 * 1024) // 4


def evaluate(health, status, disk, options, previous, now, queue_file_bytes=None):
    """Returns (verdict, findings, metrics, state). Pure: no I/O."""
    findings = []
    metrics = {"bower_up": 1 if health is not None else 0}

    def find(level, code, detail):
        findings.append({"level": NAMES[level], "code": code, "detail": detail})

    if health is None:
        find(CRITICAL, "collector-unreachable", "The collector did not answer /health.")
    else:
        degraded = health.get("status") != "healthy"
        metrics["bower_health_degraded"] = 1 if degraded else 0
        if degraded:
            find(WARNING, "health-degraded", "The collector reports degraded (dead letters or an overdue source).")

    state = {"startedAt": None, "syslog": {}, "windowsEventLog": {}}
    if status is not None:
        queue = status.get("queue") or {}
        undelivered = sum(int(queue.get(key) or 0) for key in ("queued", "retrying", "uploading"))
        dead = int(queue.get("deadLettered") or 0)
        undelivered_bytes = int(queue.get("undeliveredBytes") or 0)
        oldest = parse_time(queue.get("oldestUndelivered"))
        age = max(0, int((now - oldest).total_seconds())) if oldest else 0
        used = 100.0 * undelivered_bytes / options.queue_max_bytes if options.queue_max_bytes > 0 else 0.0
        metrics.update({
            "bower_queue_undelivered_events": undelivered,
            "bower_queue_dead_lettered_events": dead,
            "bower_queue_undelivered_bytes": undelivered_bytes,
            "bower_queue_oldest_undelivered_age_seconds": age,
            "bower_queue_capacity_used_percent": round(used, 2),
        })
        if dead > 0:
            find(WARNING, "dead-letters", f"{dead} event(s) set aside; review and use the audited replay.")
        if age >= options.backlog_critical_seconds:
            find(CRITICAL, "backlog", f"Oldest undelivered event is {age} s old.")
        elif age >= options.backlog_warning_seconds:
            find(WARNING, "backlog", f"Oldest undelivered event is {age} s old.")
        if used >= options.storage_critical_percent:
            find(CRITICAL, "queue-storage", f"Undelivered data is {used:.1f}% of BOWER_QUEUE_MAX_BYTES.")
        elif used >= options.storage_warning_percent:
            find(WARNING, "queue-storage", f"Undelivered data is {used:.1f}% of BOWER_QUEUE_MAX_BYTES.")

        intake = status.get("intake") or {}
        refusals = int(intake.get("capacityRefusals") or 0) + int(intake.get("privacyAlertRefusals") or 0)
        metrics["bower_intake_capacity_refusals_total"] = refusals
        last_refusal = parse_time(intake.get("lastRefusalAt"))
        if last_refusal and (now - last_refusal).total_seconds() <= options.refusal_window_seconds:
            find(CRITICAL, "capacity-refusals", "Intake was refused for queue capacity within the refusal window.")

        overdue = [item for item in (status.get("sources") or []) if item.get("state") in ("silent", "never-seen")]
        metrics["bower_sources_overdue"] = len(overdue)
        for item in overdue[:10]:
            find(WARNING, "source-overdue", f"{item.get('application')}/{item.get('environment')} is {item.get('state')}.")

        started = intake.get("observedSince")
        state["startedAt"] = started
        same_process = previous.get("startedAt") == started and started is not None
        for listener in status.get("syslog") or []:
            key = str(listener.get("id"))
            errors = sum(int(listener.get(name) or 0) for name in SYSLOG_ERRORS)
            accepted = int(listener.get("connectionsAccepted") or 0)
            state["syslog"][key] = {"errors": errors, "accepted": accepted}
            metrics[f'bower_syslog_errors_total{{listener="{key}"}}'] = errors
            metrics[f'bower_syslog_connections_accepted_total{{listener="{key}"}}'] = accepted
            metrics[f'bower_syslog_active_connections{{listener="{key}"}}'] = int(listener.get("activeConnections") or 0)
            before = previous.get("syslog", {}).get(key) if same_process else None
            if before is not None and errors > before.get("errors", 0):
                find(WARNING, "syslog-errors", f"Listener {key}: {errors - before['errors']} new refusal/TLS/framing/drop error(s).")
            if before is not None and accepted - before.get("accepted", 0) > options.churn_warning_connections:
                find(WARNING, "syslog-churn", f"Listener {key}: {accepted - before['accepted']} new connections since the last run.")
        for subscription in status.get("windowsEventLog") or []:
            key = str(subscription.get("id"))
            errors = sum(int(subscription.get(name) or 0) for name in WINDOWS_ERRORS)
            state["windowsEventLog"][key] = {"errors": errors}
            metrics[f'bower_windows_event_log_errors_total{{subscription="{key}"}}'] = errors
            if subscription.get("state") not in ("starting", "running", "backpressure"):
                find(CRITICAL, "windows-event-log", f"Subscription {key} is {subscription.get('state')}.")
            before = previous.get("windowsEventLog", {}).get(key) if same_process else None
            if before is not None and errors > before.get("errors", 0):
                find(WARNING, "windows-event-log", f"Subscription {key}: {errors - before['errors']} new read error(s).")

    if queue_file_bytes is not None and options.queue_max_bytes > 0:
        # The database stops growing here ("database or disk is full") before undelivered
        # payloads reach BOWER_QUEUE_MAX_BYTES; delivery can then stall until the cap is raised.
        file_percent = 100.0 * queue_file_bytes / queue_file_limit(options.queue_max_bytes)
        metrics["bower_queue_file_bytes"] = queue_file_bytes
        metrics["bower_queue_file_limit_used_percent"] = round(file_percent, 2)
        if file_percent >= options.file_critical_percent:
            find(CRITICAL, "queue-file", f"Queue database is at {file_percent:.1f}% of its page limit.")
        elif file_percent >= options.file_warning_percent:
            find(WARNING, "queue-file", f"Queue database is at {file_percent:.1f}% of its page limit.")

    if disk is not None:
        free_percent = 100.0 * disk["free"] / disk["total"] if disk["total"] else 0.0
        metrics["bower_queue_volume_free_bytes"] = disk["free"]
        metrics["bower_queue_volume_free_percent"] = round(free_percent, 2)
        if free_percent <= options.disk_critical_percent:
            find(CRITICAL, "disk-free", f"Queue volume has {free_percent:.1f}% free.")
        elif free_percent <= options.disk_warning_percent:
            find(WARNING, "disk-free", f"Queue volume has {free_percent:.1f}% free.")

    levels = [code for code, name in NAMES.items() if any(item["level"] == name for item in findings)]
    verdict = max(levels) if levels else OK
    if verdict == OK and status is None and options.token_file:
        verdict = UNKNOWN
        findings.append({"level": "UNKNOWN", "code": "status-unavailable", "detail": "/v1/status could not be read."})
    metrics["bower_check_status"] = verdict
    return verdict, findings, metrics, state


def disk_usage(path):
    directory = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path)) or "/"
    try:
        usage = shutil.disk_usage(directory)
    except OSError:
        return None
    return {"total": usage.total, "free": usage.free}


def prometheus(metrics):
    lines = []
    for name, value in sorted(metrics.items()):
        base = name.split("{", 1)[0]
        kind = "counter" if base.endswith("_total") else "gauge"
        header = f"# TYPE {base} {kind}"
        if header not in lines:
            lines.append(header)
        lines.append(f"{name} {value}")
    return "\n".join(lines) + "\n"


def write_atomic(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".bower-healthcheck-", suffix=".prom")
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write(text)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def main(argv=None):
    options = parser().parse_args(argv)
    now = datetime.now(timezone.utc)
    base = options.url.rstrip("/")
    try:
        token = read_token(options.token_file)
    except OSError:
        print("UNKNOWN: token file unreadable")
        return UNKNOWN
    health = status = None
    try:
        health = fetch(base + "/health", None, options.timeout)
    except (urllib.error.URLError, OSError, ValueError):
        health = None
    if health is not None and token:
        try:
            status = fetch(base + "/v1/status", token, options.timeout)
        except (urllib.error.URLError, OSError, ValueError):
            status = None
    previous = load_state(options.state_file)
    try:
        queue_file_bytes = os.path.getsize(options.queue_path) if os.path.isfile(options.queue_path) else None
    except OSError:
        queue_file_bytes = None
    verdict, findings, metrics, state = evaluate(
        health, status, disk_usage(options.queue_path), options, previous, now, queue_file_bytes)
    try:
        save_state(options.state_file, state)
    except OSError:
        pass
    metrics["bower_check_timestamp_seconds"] = int(time.time())
    if options.prometheus_file:
        write_atomic(options.prometheus_file, prometheus(metrics))
    if options.format == "json":
        print(json.dumps({"status": NAMES[verdict], "checkedAt": now.isoformat(), "findings": findings,
                          "metrics": metrics}, sort_keys=True))
    elif options.format == "prometheus":
        sys.stdout.write(prometheus(metrics))
    else:
        detail = "; ".join(f"{item['code']}: {item['detail']}" for item in findings) or "collector healthy"
        print(f"{NAMES[verdict]}: {detail}")
    return verdict


if __name__ == "__main__":
    sys.exit(main())
