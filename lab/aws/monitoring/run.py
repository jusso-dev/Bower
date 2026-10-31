#!/usr/bin/env python3
"""Runs one reviewed script on one drill host through SSM and waits for the result.

Before every command it verifies the AWS account, then the exact instance ID's Project and
RunId tags and running state. Only public run metadata is injected; scripts fetch any lab
material themselves and must not print secrets. Output is bounded and recorded with the
script hash in commands.jsonl beside the state file.
"""

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

ACCOUNT = "959038055523"


def aws(profile, region, *args):
    completed = subprocess.run(["aws", "--profile", profile, "--region", region, "--output", "json", *args],
                               capture_output=True, text=True, check=True, timeout=180)
    return json.loads(completed.stdout) if completed.stdout.strip() else {}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=("Linux", "Windows"))
    parser.add_argument("script", type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--profile", default="homelab-admin")
    parser.add_argument("--region", default="ap-southeast-2")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--env", action="append", default=[], help="Extra NAME=VALUE (public values only)")
    parser.add_argument("--no-wait", action="store_true")
    args = parser.parse_args(argv)
    if not 30 <= args.timeout <= 7200:
        raise SystemExit("SSM execution timeout must be bounded")
    state = json.loads(args.state.read_text(encoding="utf-8"))
    identity = aws(args.profile, args.region, "sts", "get-caller-identity")
    if identity.get("Account") != ACCOUNT:
        raise SystemExit("Unexpected AWS account")
    instance_id = state["outputs"][args.host + "Id"]
    instance = aws(args.profile, args.region, "ec2", "describe-instances", "--instance-ids", instance_id)[
        "Reservations"][0]["Instances"][0]
    tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
    if tags.get("Project") != "bower-lab" or tags.get("RunId") != state["runId"]:
        raise SystemExit("Instance is outside this drill run")
    if instance.get("State", {}).get("Name") != "running":
        raise SystemExit("Instance is not running")
    windows = instance.get("Platform") == "windows"
    if args.script.suffix != (".ps1" if windows else ".sh"):
        raise SystemExit("Script does not match host platform")
    values = {"BOWER_LAB_BUCKET": state["outputs"]["Bucket"], "BOWER_LAB_RUN": state["runId"],
              "AWS_DEFAULT_REGION": args.region}
    values.update(item.split("=", 1) for item in args.env)
    if windows:
        prefix = "\n".join("$env:" + key + "='" + value.replace("'", "''") + "'" for key, value in values.items())
    else:
        prefix = "\n".join("export " + key + "=" + shlex.quote(value) for key, value in values.items())
    script = args.script.read_text(encoding="utf-8")
    response = aws(args.profile, args.region, "ssm", "send-command", "--instance-ids", instance_id,
                   "--document-name", "AWS-RunPowerShellScript" if windows else "AWS-RunShellScript",
                   "--parameters", json.dumps({"commands": [prefix + "\n" + script],
                                               "executionTimeout": [str(args.timeout)]}),
                   "--timeout-seconds", "600", "--comment", ("Bower " + state["runId"] + " " + args.script.name)[:100])
    command_id = response["Command"]["CommandId"]
    record = {"commandId": command_id, "instanceId": instance_id, "host": args.host, "script": args.script.name,
              "sha256": hashlib.sha256(args.script.read_bytes()).hexdigest(),
              "sentAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if args.no_wait:
        print(json.dumps(record))
        with (args.state.parent / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")
        return 0
    deadline = time.monotonic() + args.timeout + 120
    result = {}
    while time.monotonic() < deadline:
        time.sleep(5)
        try:
            result = aws(args.profile, args.region, "ssm", "get-command-invocation", "--command-id", command_id,
                         "--instance-id", instance_id)
        except subprocess.CalledProcessError:
            continue
        if result.get("Status") not in ("Pending", "InProgress", "Delayed"):
            break
    record["status"] = result.get("Status")
    record["responseCode"] = result.get("ResponseCode")
    with (args.state.parent / "commands.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    sys.stdout.write((result.get("StandardOutputContent") or "")[-20000:])
    error = (result.get("StandardErrorContent") or "")[-4000:]
    if error:
        sys.stderr.write(error)
    print(json.dumps(record), file=sys.stderr)
    return 0 if result.get("Status") == "Success" else 1


if __name__ == "__main__":
    sys.exit(main())
