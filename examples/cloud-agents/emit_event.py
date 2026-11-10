"""Append one Bower security event to a JSON-lines file for a log agent to pick up.

    python3 emit_event.py /var/log/bower/events.jsonl

The CloudWatch agent (or any agent that tails the file) ships each line as is; nothing here
talks to the network. In an application, build events with the framework helpers in
examples/asvs-logging and append them the same way: one complete JSON object per line,
UTF-8, written with a single append. Standard library only.
"""
import json
import os
import sys
import uuid
from datetime import datetime, timezone


def event(event_type: str, result: str, username: str, source_ip: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "schemaVersion": "1.0.0",
        "eventId": str(uuid.uuid4()),
        "timeGenerated": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
        "eventCategory": "authentication",
        "eventType": event_type,
        "eventAction": "authentication.login",
        "eventResult": result,
        "eventSeverity": "medium" if result != "success" else "informational",
        "application": {"name": "orders-api", "environment": "production"},
        "actor": {"type": "human", "username": username},
        "source": {"ipAddress": source_ip},
    }


def append(path: str, record: dict) -> None:
    line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
    # O_APPEND makes each write land at the end, so concurrent writers never interleave
    # inside a line shorter than the pipe buffer.
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/var/log/bower/events.jsonl"
    append(target, event("authentication_failure", "failure", "alice@example.com", "203.0.113.24"))
    print(f"appended one event to {target}")
