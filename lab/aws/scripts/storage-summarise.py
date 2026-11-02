#!/usr/bin/env python3
"""Summarise storage-pressure scenario journals (metadata-only JSON lines) per run.

A journal can hold several runs of one scenario (each starts with a "generating"
event); every run is summarised separately so failed attempts stay visible.
"""
import argparse
import datetime as dt
import json
import re
from pathlib import Path


def when(value):
    text = re.sub(r"\.(\d+)(?=[Z+-])", lambda match: "." + (match.group(1) + "000000")[:6], value)
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def runs(path):
    found, current = [], None
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("kind") == "event" and record.get("event") == "generating":
            current = {"events": [], "samples": []}
            found.append(current)
        if current is not None:
            current["events" if record.get("kind") == "event" else "samples"].append(record)
    return found


def seconds(start, end):
    return None if start is None or end is None else round((when(end) - when(start)).total_seconds(), 1)


def summarise(run):
    events, samples = run["events"], run["samples"]
    at = {event["event"]: event["at"] for event in events}
    first = lambda predicate: next((row["at"] for row in samples if predicate(row)), None)
    numbers = lambda key: [row[key] for row in samples if isinstance(row.get(key), (int, float))]
    refusal_key = "listenerRetries" if any("listenerRetries" in row for row in samples) else "sourceRetries"
    baseline = samples[0].get(refusal_key) or 0 if samples else 0
    blocked, restored = at.get("destination-blocked"), at.get("destination-restored") or at.get("destination-restored-while-full")
    lag = [row["forwardedRecords"] - row["bookmarkRecordId"] for row in samples
           if isinstance(row.get("forwardedRecords"), int) and isinstance(row.get("bookmarkRecordId"), int)]
    summary = {
        "startedAt": events[0]["at"], "endedAt": samples[-1]["at"] if samples else None,
        "events": [{key: value for key, value in event.items() if key != "kind"} for event in events],
        "samples": len(samples),
        "firstRefusalAt": first(lambda row: (row.get(refusal_key) or 0) > baseline),
        "firstWarningAt": first(lambda row: row.get("storageState") in ("warning", "critical")),
        "firstCriticalAt": first(lambda row: row.get("storageState") == "critical"),
        "secondsBlockedToRefusal": seconds(blocked, first(lambda row: (row.get(refusal_key) or 0) > baseline)),
        "maximumPageUtilisation": max(numbers("pageUtilisation"), default=None),
        "maximumUndeliveredBytes": max(numbers("undeliveredBytes"), default=None),
        "maximumQueueFileBytes": max(numbers("queueFileBytes"), default=None),
        "minimumFreeBytes": min(numbers("freeBytes"), default=None),
        "maximumOldestPendingAge": max(numbers("oldestPendingAge"), default=None),
        "maximumSenderQueue": max(numbers("senderQueue"), default=None),
        "maximumForwardedLag": max(lag, default=None),
        "refusals": (samples[-1].get(refusal_key) or 0) - baseline if samples else None,
        "drained": at.get("drained") is not None and any(e["event"] == "drained" and e.get("met") for e in events),
        "secondsRestoredToDrained": seconds(restored, at.get("drained")),
        "statusUnavailableSamples": sum(1 for row in samples if row.get("statusError")),
        "final": samples[-1] if samples else None,
    }
    for key in ("listenerSubmitFailures", "listenerDropped", "sourceSubmitFailures", "sourceGaps", "senderDiscarded"):
        if samples and key in samples[-1]:
            summary[key] = samples[-1][key]
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("journal", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = [summarise(run) for run in runs(args.journal)]
    args.output.write_text(json.dumps({"journal": args.journal.name, "runs": result}, indent=1) + "\n")
    for index, run in enumerate(result):
        print(index, run["startedAt"], run["secondsBlockedToRefusal"], run["refusals"], run["drained"],
              run["secondsRestoredToDrained"], run["maximumPageUtilisation"], run["maximumQueueFileBytes"])


if __name__ == "__main__":
    main()
