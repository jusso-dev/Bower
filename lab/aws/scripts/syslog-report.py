#!/usr/bin/env python3
"""Summarise syslog delivery-reliability scenario results (metadata only).

Reads the per-scenario JSON written by syslog-campaign.py and prints a Markdown table
and a JSON summary. A scenario passes only when every expected sequence key reached
the Bower queue and no accepted key for the listener is malformed. Older results
recorded an `unexpectedInScope` count that wrongly included neighbouring scenarios;
it is ignored here and the exact missing count decides.
"""
import argparse
import json
from pathlib import Path

LISTENERS = {"a13": "TLS 1.3", "a12": "TLS 1.2 pinned", "b13i": "TLS 1.3, idle 3600 s",
             "b13n": "TLS 1.3, idle 0", "b12i": "TLS 1.2 pinned, idle 3600 s"}


def summarise(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    invalid = record.get("invalid")
    rows = []
    for key, measurement in sorted(record.get("measurements", {}).items()):
        if not isinstance(measurement, dict) or "listeners" not in measurement:
            continue
        phase = key.split("-", 1)[1] if "-" in key else ""
        for listener, value in sorted(measurement["listeners"].items()):
            missing = value["missing"]
            malformed = value.get("malformedKeys", 0)
            duplicates = None
            syslog = measurement.get("syslog") or {}
            if listener in syslog:
                duplicates = syslog[listener].get("duplicates")
            rows.append({"scenario": path.stem, "phase": phase, "collector": key.split("-")[0],
                         "listener": listener, "transport": LISTENERS.get(listener, listener),
                         "expected": value["expected"], "accepted": value["accepted"], "missing": missing,
                         "malformedKeys": malformed, "duplicatesSinceStart": duplicates,
                         "missingSample": value["missingSample"][:5], "invalid": invalid,
                         "passed": not invalid and missing == 0 and malformed == 0})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("scenario", nargs="+")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    rows = [row for name in args.scenario for row in summarise(args.evidence / (name + ".json"))]
    print("| Scenario | Phase | Listener | Expected | Accepted | Lost | Result |")
    print("|---|---|---|---:|---:|---:|---|")
    for row in rows:
        print("| `{scenario}` | {phase} | `{listener}` ({transport}) | {expected:,} | {accepted:,} | {missing:,} | {result} |".format(
            result="invalid (harness)" if row["invalid"] else "pass" if row["passed"] else "**fail**", **row))
    if args.json:
        args.json.write_text(json.dumps({"rows": rows, "passed": all(r["passed"] for r in rows)}, indent=1) + "\n",
                             encoding="utf-8")


if __name__ == "__main__":
    main()
