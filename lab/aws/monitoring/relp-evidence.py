#!/usr/bin/env python3
"""Publish one RELP campaign's private scenario directories as sanitized public evidence.

Reads the attempt directories relp-scenario.py wrote and writes, per attempt, the redacted
plan, generator/fault/measure/snapshot reports, reconciliation report and compact JSONL
identity sidecars, plus summary.json and public-manifest.json with SHA-256 hashes. Local
operator paths are the only content changed: plan.json carries them in its SSM argument
arrays, so the public copy replaces them and records both the original and redacted hash
(the reconciliation report binds the original). Every published file is checked to contain
no local path. Synthetic identities and timestamps only; no payloads or credentials.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

COPY = re.compile(r"\d{2}-(native-generator-result|queue-acceptance-only|collector-snapshot|sender-snapshot)\.json"
                  r"|fault-[a-z-]+-\d+\.json|reconciliation-\d+\.json|summary\.json|destination-block-(applied|restored)\.json|dedup-proof\.json"
                  r"|mid-outage-snapshot\.json|health-records-during-refusal\.json")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def redact(text, home):
    return text.replace(str(home), "<operator-home>")


def outcome(record):
    queue, sentinel = record.get("queue", {}), record.get("sentinel", {})
    if not record.get("identityComplete"):
        return "**FAIL**: {} missing at the queue, {} at Sentinel".format(queue.get("missing"), sentinel.get("missing"))
    proof = record.get("dedupProof", {})
    duplicates = proof["RawRows"] - proof["DistinctIds"] if proof else sentinel.get("duplicateRows")
    if not duplicates:
        return "PASS (strict: 0 missing, 0 duplicate rows)"
    return "PASS: 0 missing; {} duplicate Sentinel rows{}".format(
        duplicates, ", collapse to {}".format(proof["CollapsedRows"]) if proof.get("collapses") else "")


def table(scenarios):
    rows = ["| Scenario | Attempt | Sender rsyslog | Native | Queue distinct (missing) | Sentinel distinct (missing) | Sentinel rows at reconciliation / final | Outcome |",
            "|---|---|---|---|---|---|---|---|"]
    for record in sorted(scenarios, key=lambda item: item["startEpoch"]):
        queue, sentinel, native = record.get("queue", {}), record.get("sentinel", {}), record.get("native", {})
        final = record.get("dedupProof", {}).get("RawRows", "n/a")
        rows.append("| `{}` | {} | {} | {} | {} ({}) | {} ({}) | {} / {} | {} |".format(
            record["scenario"], record["attempt"].rsplit("-attempt", 1)[1], record.get("senderRsyslog", "?"),
            native.get("nativeCounterDelta"), queue.get("distinctIds"), queue.get("missing"),
            sentinel.get("distinctIds"), sentinel.get("missing"), sentinel.get("rows"), final, outcome(record)))
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private", type=Path, help="Private evidence root (relp-scenario.py --evidence)")
    parser.add_argument("public", type=Path, help="New public evidence directory")
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--sender-upgrade-epoch", type=float,
                        help="When the sender moved to rsyslog 8.2610.0; earlier attempts used 8.2204.0")
    args = parser.parse_args()
    out = args.public
    out.mkdir(parents=True, exist_ok=True)
    scenarios = []
    for attempt in sorted(path for path in args.private.iterdir() if path.is_dir() and "-attempt" in path.name):
        if not (attempt / "summary.json").exists():
            print("skipping attempt still in progress: " + attempt.name, file=sys.stderr)
            continue
        target = out / "scenarios" / attempt.name
        target.mkdir(parents=True, exist_ok=True)
        plan_bytes = (attempt / "plan.json").read_bytes()
        redacted_plan = redact(plan_bytes.decode(), args.home).encode()
        (target / "plan.json").write_bytes(redacted_plan)
        record = {"attempt": attempt.name, "planSha256": sha(plan_bytes), "publicPlanSha256": sha(redacted_plan)}
        for path in sorted(attempt.iterdir()):
            if COPY.fullmatch(path.name):
                (target / path.name).write_text(redact(path.read_text(), args.home))
        # A reconcile-only pass re-exports into queue-identities-N.json; publish every export.
        for queue_file in sorted(attempt.glob("queue-identities*.json")):
            queue = json.loads(queue_file.read_text())
            rows = "".join(json.dumps([row["eventId"], row["generatedAt"], row["receivedAt"]]) + "\n" for row in queue["rows"])
            (target / (queue_file.stem + ".jsonl")).write_text(rows)
            record.setdefault("queueExports", []).append({"file": queue_file.stem + ".jsonl", "exportSha256": sha(queue_file.read_bytes()),
                                                          "rows": len(queue["rows"]), "helperSha256": queue.get("helperSha256")})
        for rows_file in sorted(attempt.glob("sentinel-rows-*.json")):
            data = json.loads(rows_file.read_text())
            lines = "".join(json.dumps(row) + "\n" for row in data["rows"])
            (target / rows_file.name.replace(".json", ".jsonl")).write_text(lines)
            envelope = {key: value for key, value in data.items() if key != "rows"}
            envelope["rowsFile"] = rows_file.name.replace(".json", ".jsonl")
            envelope["originalSha256"] = sha(rows_file.read_bytes())
            (target / rows_file.name.replace(".json", "-query.json")).write_text(json.dumps(envelope, indent=1) + "\n")
        summary = json.loads((attempt / "summary.json").read_text())
        reports = sorted(attempt.glob("reconciliation-*.json"), key=lambda path: int(path.stem.split("-")[1]))
        if reports:
            report = json.loads(reports[-1].read_text())
            record.update({key: report.get(key) for key in ("expected", "identityComplete", "strictPass", "queryCutoff")})
            for stage in ("native", "queue", "sentinel"):
                record[stage] = {key: value for key, value in report.get(stage, {}).items()
                                 if key in ("expected", "sent", "nativeCounterDelta", "distinctIds", "missing", "extra",
                                            "rows", "duplicateRows", "identitySetSha256", "actualRates",
                                            "firstIngested", "lastIngested")}
        record["scenario"] = summary["scenario"]
        record["startEpoch"] = json.loads(plan_bytes)["startEpoch"]
        if args.sender_upgrade_epoch:
            record["senderRsyslog"] = "8.2610.0" if record["startEpoch"] > args.sender_upgrade_epoch else "8.2204.0"
        proof = attempt / "dedup-proof.json"
        if proof.exists():
            record["dedupProof"] = {key: value for key, value in json.loads(proof.read_text()).items()
                                    if key in ("RawRows", "CollapsedRows", "DistinctIds", "collapses")}
        record["queries"] = summary.get("queries", [])
        record["faults"] = [{"action": fault["action"], "host": fault["host"], "record": fault["record"]}
                            for fault in summary.get("faults", [])]
        snapshot = next(iter(sorted(attempt.glob("*-collector-snapshot.json"))), None)
        if snapshot is not None:
            status = json.loads(snapshot.read_text()).get("syslog", {}).get("a13", {})
            record["relpCountersSinceCollectorStart"] = {key: status.get(key) for key in (
                "connectionsAccepted", "framesReceived", "queued", "duplicates", "relpAcknowledged",
                "relpServerCloses", "relpBusyCloses", "retries", "framingErrors", "tlsHandshakeFailures",
                "peerResets", "oversized", "malformed")}
        scenarios.append(record)
    (out / "summary.json").write_text(json.dumps({"schemaVersion": 1, "scenarios": scenarios}, indent=1) + "\n")
    (out / "results-table.md").write_text(table(scenarios))
    manifest = {}
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "public-manifest.json":
            data = path.read_bytes()
            if b"/Users/" in data or b"/home/" in data:
                raise SystemExit("local path left in " + str(path.relative_to(out)))
            manifest[str(path.relative_to(out))] = {"bytes": len(data), "sha256": sha(data)}
    (out / "public-manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    print(json.dumps({"scenarios": len(scenarios), "files": len(manifest)}))


if __name__ == "__main__":
    main()
