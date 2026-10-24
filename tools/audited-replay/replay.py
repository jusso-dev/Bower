#!/usr/bin/env python3
"""Offline, one-shot audit wrapper for a trusted compiled Bower CLI (POSIX)."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


MAX_EVENTS = 100
MAX_ID_LENGTH = 128
MAX_METADATA_LENGTH = 80
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]*", re.ASCII)


class Refused(Exception):
    """Only fixed, payload-free error codes may be supplied."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default diagnostics can echo arbitrary user input.
        raise Refused("invalid-arguments")


def parser():
    result = Parser(description=__doc__, allow_abbrev=False)
    result.add_argument("--cli", required=True, help="Trusted compiled CLI/apphost path")
    result.add_argument("--database", required=True, help="Existing offline queue path")
    result.add_argument("--audit-directory", required=True, help="New directory; parent must exist")
    result.add_argument("--operator", required=True, help="Non-secret operator identifier")
    result.add_argument("--change-reference", required=True, help="Approved change identifier")
    result.add_argument("--event", required=True, action="append", help="Exact reviewed ID; repeatable")
    result.add_argument("--timeout-seconds", type=int, default=60)
    return result


def identifier(value, maximum):
    return 1 <= len(value) <= maximum and IDENTIFIER.fullmatch(value) is not None


def existing_file(value):
    if len(value) > 4096 or "\x00" in value:
        raise Refused("invalid-path")
    path = Path(value).resolve(strict=True)
    if not path.is_file():
        raise Refused("invalid-file")
    return path


def validate(args):
    if not 1 <= len(args.event) <= MAX_EVENTS or len(set(args.event)) != len(args.event):
        raise Refused("invalid-event-batch")
    if not all(identifier(event, MAX_ID_LENGTH) for event in args.event):
        raise Refused("invalid-event-id")
    if not all(identifier(value, MAX_METADATA_LENGTH)
               for value in (args.operator, args.change_reference)):
        raise Refused("invalid-audit-metadata")
    if not 1 <= args.timeout_seconds <= 300:
        raise Refused("invalid-timeout")
    if len(args.audit_directory) > 4096 or "\x00" in args.audit_directory:
        raise Refused("invalid-path")
    cli = existing_file(args.cli)
    database = existing_file(args.database)
    if not os.access(cli, os.X_OK):
        raise Refused("cli-not-executable")
    return cli, database


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def path_digest(path):
    return hashlib.sha256(os.fsencode(path)).hexdigest()


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_audit_directory(path):
    # Parent is pre-provisioned private storage, not silently created on demand.
    parent = path.parent.resolve(strict=True)
    parent_stat = parent.stat()
    if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
        raise Refused("audit-parent-must-be-private-and-owned")
    directory = parent / path.name
    directory.mkdir(mode=0o700)  # Exclusive: even an empty prior attempt is refused.
    sync_directory(parent)
    return directory


def persist(directory, name, record):
    """Publish only complete records; keep temporary evidence on any failure."""
    data = (json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    pending = directory / (name + ".pending")
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())
    # link is an atomic publish that cannot replace an existing record.
    os.link(pending, directory / name, follow_symlinks=False)
    sync_directory(directory)
    pending.unlink()
    sync_directory(directory)


def execute(args):
    cli, database = validate(args)
    command = [str(cli), "queue", "replay", "--database", str(database), "--max", str(len(args.event))]
    for event in args.event:
        command.extend(["--event", event])
    database_stat = database.stat()
    operation_id = str(uuid.uuid4())
    intent = {
        "schema_version": 1,
        "operation_id": operation_id,
        "record_type": "intent",
        "timestamp_utc": timestamp(),
        "operator": args.operator,
        "change_reference": args.change_reference,
        "event_ids": args.event,
        "maximum_count": len(args.event),
        "timeout_seconds": args.timeout_seconds,
        "command": "queue replay --database <database_path_sha256> --max <maximum_count> --event <each event_id>",
        "cli_path_sha256": path_digest(cli),
        "cli_file_sha256": file_digest(cli),
        "database_path_sha256": path_digest(database),
        "database_device": database_stat.st_dev,
        "database_inode": database_stat.st_ino,
        "delivery_verified": False,
    }
    directory = create_audit_directory(Path(args.audit_directory))
    persist(directory, "intent.json", intent)
    # No CLI output is read, retained, printed or included in the audit.
    exit_code = None
    try:
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, shell=False, check=False,
                                   timeout=args.timeout_seconds)
        exit_code = completed.returncode
        status = "cli-exit-zero" if exit_code == 0 else "cli-exit-nonzero"
    except subprocess.TimeoutExpired:
        status = "timeout"
    except KeyboardInterrupt:
        status = "interrupted"
    except OSError:
        status = "launch-failed"
    outcome = {
        "schema_version": 1,
        "operation_id": operation_id,
        "record_type": "outcome",
        "timestamp_utc": timestamp(),
        "status": status,
        "cli_exit_code": exit_code,
        # Even a zero exit can replay fewer than the selected IDs. Do not invent counts.
        "queue_effect": "unverified" if status == "cli-exit-zero" else "ambiguous",
        "delivery_verified": False,
    }
    try:
        persist(directory, "outcome.json", outcome)
    except OSError:
        raise Refused("outcome-audit-failed-reconcile-before-any-retry") from None
    return 0 if status == "cli-exit-zero" else 1


def main(argv=None):
    try:
        result = execute(parser().parse_args(argv))
    except Refused as error:
        print(str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError):
        # No exception messages: paths and CLI/OS diagnostics can contain secrets.
        print("local-validation-or-intent-audit-failed-no-cli-invocation", file=sys.stderr)
        return 2
    if result == 0:
        print("CLI exited zero; audit saved. Replay count and destination delivery remain unverified.")
    else:
        print("CLI did not complete successfully; audit saved. Reconcile before any retry.", file=sys.stderr)
    return result


if __name__ == "__main__":
    sys.exit(main())
