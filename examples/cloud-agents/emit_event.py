"""Append one Bower security event to a JSON-lines file for a log agent to pick up.

    python3 emit_event.py /var/log/bower/events.jsonl
    python3 emit_event.py /var/log/bower/events.jsonl --application orders-api \\
        --environment staging --username alice@example.com --source-ip 203.0.113.24

The CloudWatch agent (or any agent that tails the file) ships each line as is; nothing here
talks to the network. In an application, build events with the framework helpers in
examples/asvs-logging and append them the same way: one complete JSON object per line,
UTF-8, written with a single append. Standard library only.

Notes for anyone copying this into an application:

- File mode: os.open's 0o660 is reduced by the process umask, so a file this script creates
  itself is usually 0640. The quick start pre-creates the file as root:bower-events 0660, so
  this only shows when you point the script somewhere else.
- No fsync: the line is in the page cache when this returns, so an event can be lost if the
  server loses power straight after the write. Call os.fsync(fd) before closing if that
  matters more than the cost of a disk flush per event.
- If the file doesn't end with a line break (an earlier writer was cut short), the event is
  written on a new line, so the damage stays with the earlier fragment.
"""
import argparse
import json
import os
import uuid
from datetime import datetime, timezone

DEFAULT_PATH = "/var/log/bower/events.jsonl"


def event(event_type: str, result: str, username: str, source_ip: str,
          application: str = "orders-api", environment: str = "production") -> dict:
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
        "application": {"name": application, "environment": environment},
        "actor": {"type": "human", "username": username},
        "source": {"ipAddress": source_ip},
    }


def append(path: str, record: dict) -> None:
    line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
    data = line.encode("utf-8")
    # Concurrent writers are safe on a local Linux file system when each line goes out like this:
    # - O_APPEND on a regular file moves to the end and writes in one step, whatever the length
    #   (the 4 KiB PIPE_BUF limit is for pipes and FIFOs, not files);
    # - the whole line goes out in ONE write call. Buffered writers (a default print() to a
    #   file, a logging handler) can split a line across writes, and another writer can land
    #   between the pieces;
    # - network file systems (NFS) don't give the O_APPEND guarantee, and on Windows the C
    #   runtime emulates O_APPEND with a seek, so keep one writer per file there.
    # O_BINARY (Windows only) stops "\n" turning into "\r\n".
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o660)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        if size > 0:
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) != b"\n":
                data = b"\n" + data
        written = os.write(fd, data)
    finally:
        os.close(fd)
    if written != len(data):
        # A short write (for example a full disk) leaves a partial line. Don't retry here:
        # another writer may already have appended after it. Report it so it can be fixed.
        raise OSError(f"short write to {path}: {written} of {len(data)} bytes; the last line is incomplete")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Append one Bower test event to a JSON-lines file.")
    parser.add_argument("path", nargs="?", default=DEFAULT_PATH, help=f"file to append to (default {DEFAULT_PATH})")
    parser.add_argument("--application", default="orders-api", help="application.name (default orders-api)")
    parser.add_argument("--environment", default="production", help="application.environment (default production)")
    parser.add_argument("--username", default="alice@example.com", help="actor.username")
    parser.add_argument("--source-ip", default="203.0.113.24", help="source.ipAddress")
    args = parser.parse_args(argv)
    record = event("authentication_failure", "failure", args.username, args.source_ip,
                   args.application, args.environment)
    append(args.path, record)
    print(f"appended event {record['eventId']} to {args.path}")


if __name__ == "__main__":
    main()
