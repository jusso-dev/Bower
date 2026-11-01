#!/usr/bin/env python3
"""Run one frozen firewall scenario end to end and keep every artifact.

Plans with syslog-plan.py, installs the scenario's ingestion-only destination block
(destination-outage.sh) when the plan requires one, dispatches the steps through the
ownership-checking run.py, waits for collection, gathers the generator/fault/measure
reports, exports queue identities, then queries Sentinel with the separate verifier
(query-firewall.py). Every attempt gets a new directory; nothing is overwritten, so a
failed attempt stays beside its rerun. Output is metadata only.
"""

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / "scripts"
PROFILE, REGION = "homelab-admin", "ap-southeast-2"


def log(message):
    print(dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S ") + message, flush=True)


def aws(*args):
    result = subprocess.run(["aws", "--profile", PROFILE, "--region", REGION, "--output", "json", *args],
                            capture_output=True, text=True, timeout=300)
    if result.returncode:
        raise RuntimeError("AWS call failed: " + " ".join(args[:2]))
    return json.loads(result.stdout) if result.stdout.strip() else {}


def run_host(state, host, script, env, timeout=900):
    """run.py with public env values; returns (exit code, stdout)."""
    argv = [sys.executable, str(HERE / "run.py"), host, str(script), "--state", str(state), "--timeout", str(timeout)]
    for key, value in env.items():
        argv += ["--env", key + "=" + value]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 400)
    return result.returncode, result.stdout


def last_json(text):
    """The last JSON document a host command printed (helpers print one record)."""
    text = text.strip()
    for start in [index for index, char in enumerate(text) if char == "{"]:
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            continue
    return None


def wait_online(state, host, deadline):
    instance = json.loads(Path(state).read_text())["outputs"][host + "Id"]
    while time.time() < deadline:
        info = aws("ssm", "describe-instance-information", "--filters", "Key=InstanceIds,Values=" + instance)
        if any(item.get("PingStatus") == "Online" for item in info.get("InstanceInformationList", [])):
            return True
        time.sleep(15)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--azure-state-dir", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True, help="Private evidence root; a new attempt directory is created")
    parser.add_argument("--pack-sha256", required=True)
    parser.add_argument("--sequence-offset", default="0")
    parser.add_argument("--lead-seconds", type=int, default=180)
    parser.add_argument("--ingestion-wait-seconds", type=int, default=600)
    parser.add_argument("--reconcile-only", type=Path,
                        help="Existing attempt directory: export and query again into new files (no dispatch)")
    args = parser.parse_args()
    state = json.loads(args.state.read_text())
    outputs = state["outputs"]
    if args.reconcile_only:
        root = args.reconcile_only
        plan = json.loads((root / "plan.json").read_text())
        summary = json.loads((root / "summary.json").read_text()) if (root / "summary.json").exists() else {
            "scenario": plan["scenario"], "runId": state["runId"]}
        summary.setdefault("reconciliationRetries", []).append(dt.datetime.now(dt.timezone.utc).isoformat())
        reconcile(args, state, root, plan, summary, 0)
        return
    attempt = 1
    while (args.evidence / "{}-attempt{}".format(args.scenario, attempt)).exists():
        attempt += 1
    root = args.evidence / "{}-attempt{}".format(args.scenario, attempt)
    root.mkdir(parents=True, mode=0o700)
    summary = {"scenario": args.scenario, "attempt": attempt, "runId": state["runId"]}

    start = time.time() + args.lead_seconds
    planned = subprocess.run([sys.executable, str(HERE / "syslog-plan.py"), args.scenario, "--source", str(SCRIPTS),
                              "--state", str(args.state), "--collector-ip", outputs["LinuxIp"],
                              "--sender-ip", outputs["SenderIp"], "--start-epoch", "{:.3f}".format(start),
                              "--sequence-offset", args.sequence_offset], capture_output=True, text=True, check=True)
    (root / "plan.json").write_text(planned.stdout)
    plan = json.loads(planned.stdout)
    plan_hash = hashlib.sha256((root / "plan.json").read_bytes()).hexdigest()
    summary.update(planSha256=plan_hash, startEpoch=plan["startEpoch"], expectedBlocks=plan["expectedBlocks"])
    log("{} attempt {} plan {} starts {}".format(args.scenario, attempt, plan_hash[:12],
                                                 dt.datetime.fromtimestamp(start, dt.timezone.utc).isoformat()))

    requirement = plan.get("externalFaultRequirement")
    if requirement:
        code, out = run_host(args.state, "Linux", HERE / "destination-outage.sh", {
            "BOWER_PLAN_SHA256": plan_hash, "BOWER_GENERATION_START_EPOCH": "{:.3f}".format(plan["startEpoch"]),
            "BOWER_OUTAGE_SECONDS": str(requirement["minimumVerifiedDurationSeconds"]),
            "BOWER_SCENARIO": args.scenario}, timeout=300)
        (root / "destination-block-applied.json").write_text(out)
        summary["destinationBlock"] = {"exit": code, "applied": last_json(out)}
        if code:
            summary["outcome"] = "destination block failed; scenario not started"
            (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            raise SystemExit("destination block failed")

    def dispatch(step):
        argv = step["command"]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=1200)
        return {"host": step["host"], "offsetSeconds": step["offsetSeconds"], "exit": result.returncode,
                "output": last_json(result.stdout)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        summary["steps"] = list(pool.map(dispatch, plan["steps"]))
    log("dispatched {} steps: exits {}".format(len(plan["steps"]), [step["exit"] for step in summary["steps"]]))

    wait = plan["collectNotBeforeEpoch"] - time.time()
    if wait > 0:
        log("waiting {:.0f}s for collection".format(wait))
        time.sleep(wait)
    for host in ("Linux", "Sender"):
        if not wait_online(args.state, host, time.time() + 900):
            log(host + " did not come back online")

    collected = []
    for index, item in enumerate(plan["collect"]):
        command = item["command"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=7200)
        document = last_json(result.stdout)
        name = "{:02d}-{}.json".format(index, item["kind"])
        (root / name).write_text(json.dumps(document, indent=1) + "\n" if document is not None else result.stdout)
        collected.append({"kind": item["kind"], "file": name, "exit": result.returncode})
    summary["collected"] = collected

    # Actual fault records written by the helper on each host.
    faults = []
    for step in plan["steps"]:
        text = " ".join(step["command"])
        if "fault --action" not in text:
            continue
        action = text.split("fault --action ", 1)[1].split()[0]
        at = int(float(text.split("--at ", 1)[1].split()[0]))
        code, out = run_host(args.state, step["host"], SCRIPTS / "syslog-host.sh", {
            "BOWER_LAB_HOST": "SenderR" if step["host"] == "Sender" else "CollectorA",
            "BOWER_ARGS": "result --label fault-{}-{}".format(action, at)})
        record = last_json(out)
        (root / "fault-{}-{}.json".format(action, at)).write_text(json.dumps(record, indent=1) + "\n")
        faults.append({"action": action, "host": step["host"], "record": record})
    summary["faults"] = faults
    reconcile(args, state, root, plan, summary, args.ingestion_wait_seconds)


def reconcile(args, state, root, plan, summary, ingestion_wait):
    """Export queue identities and query Sentinel; every file name is new for this pass."""
    outputs = state["outputs"]
    plan_hash = hashlib.sha256((root / "plan.json").read_bytes()).hexdigest()
    exports = len(list(root.glob("queue-identities*.json")))
    code, out = run_host(args.state, "Linux", HERE / "export-firewall-queue.sh", {
        "BOWER_SCENARIO": args.scenario, "BOWER_PLAN_SHA256": plan_hash,
        "BOWER_EXPECTED_BLOCKS": ",".join(plan["expectedBlocks"]),
        "BOWER_SCOPE_START_EPOCH": "{:.3f}".format(plan["startEpoch"] - 2),
        "BOWER_SCOPE_END_EPOCH": "{:.3f}".format(plan["collectNotBeforeEpoch"])}, timeout=300)
    export = last_json(out)
    summary.setdefault("queueExports", []).append(export)
    if code or not export or "key" not in export:
        summary["outcome"] = "queue export failed"
        (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        raise SystemExit("queue export failed")
    queue = root / ("queue-identities.json" if exports == 0 else "queue-identities-{}.json".format(exports + 1))
    subprocess.run(["aws", "--profile", PROFILE, "--region", REGION, "s3", "cp", "--only-show-errors",
                    "s3://" + outputs["Bucket"] + "/" + export["key"], str(queue)], check=True, timeout=300)
    if hashlib.sha256(queue.read_bytes()).hexdigest() != export["sha256"]:
        raise SystemExit("queue export hash mismatch")

    natives = [root / name for name in sorted(path.name for path in root.glob("*-native-generator-result.json"))]
    time.sleep(max(0, ingestion_wait))
    first = len(list(root.glob("reconciliation-*.json"))) + 1
    for query in range(first, first + 3):
        report, rows = root / "reconciliation-{}.json".format(query), root / "sentinel-rows-{}.json".format(query)
        argv = [sys.executable, str(HERE / "query-firewall.py"), "--plan", str(root / "plan.json"),
                "--queue", str(queue), "--pack-sha256", args.pack_sha256,
                "--azure-state-dir", str(args.azure_state_dir), "--output", str(report), "--destination-evidence", str(rows)]
        for native in natives:
            argv += ["--native", str(native)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=900)
        outcome = last_json(result.stdout) or {}
        summary.setdefault("queries", []).append({"query": query, "exit": result.returncode, "report": report.name,
                                                  "strictPass": outcome.get("strictPass"),
                                                  "identityComplete": outcome.get("identityComplete")})
        log("query {} exit {} identityComplete {} strictPass {}".format(
            query, result.returncode, outcome.get("identityComplete"), outcome.get("strictPass")))
        # Stop once identities are complete; a duplicate-only failure will not change with time.
        if result.returncode == 0 or outcome.get("identityComplete"):
            break
        time.sleep(300)
    summary["finishedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    log("evidence " + str(root))


if __name__ == "__main__":
    main()
