"""Run a reviewed script on an exact instance from this lab's inventory."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import shlex

from lab import aws, verify_account

HOSTS = ("Control", "Collector", "Linux1", "Linux2", "Wec", "Windows1", "Windows2")


def verify_host(instance, state):
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    if tags.get("Project") != "bower-lab" or tags.get("RunId") != state["runId"]:
        raise ValueError("Instance is outside the current lab run")
    if instance.get("State", {}).get("Name") != "running":
        raise ValueError("Instance is not running")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=HOSTS)
    parser.add_argument("script", type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--profile", default="homelab-admin")
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--phase", help="Public result label for scripts that support BOWER_LAB_PHASE")
    args = parser.parse_args()
    if args.phase and not re.fullmatch(r"[A-Za-z0-9-]{1,25}", args.phase):
        raise ValueError("Invalid phase label")
    if not 30 <= args.timeout <= 3600:
        raise ValueError("SSM execution timeout must be bounded")
    state = json.loads(args.state.read_text(encoding="utf-8"))
    verify_account(args.profile, state["region"], state["account"])
    call = lambda *parts: aws(args.profile, state["region"], *parts)
    instance_id = state["outputs"][args.host + "Id"]
    instance = call("ec2", "describe-instances", "--instance-ids", instance_id)["Reservations"][0]["Instances"][0]
    verify_host(instance, state)
    windows = instance.get("Platform") == "windows"
    if args.script.suffix != (".ps1" if windows else ".sh"):
        raise ValueError("Script does not match host platform")
    script = args.script.read_text(encoding="utf-8")
    # Only public run metadata is injected. Secrets must be retrieved on the host.
    values = {"BOWER_LAB_BUCKET": state["outputs"]["Bucket"], "BOWER_LAB_RUN": state["runId"],
              "BOWER_LAB_HOST": args.host, "AWS_DEFAULT_REGION": state["region"]}
    if args.phase:
        values["BOWER_LAB_PHASE"] = args.phase
    if windows:
        prefix = "\n".join("$env:" + key + "='" + value.replace("'", "''") + "'" for key, value in values.items())
    else:
        prefix = "\n".join("export " + key + "=" + shlex.quote(value) for key, value in values.items())
    response = call("ssm", "send-command", "--instance-ids", instance_id,
        "--document-name", "AWS-RunPowerShellScript" if windows else "AWS-RunShellScript",
        "--parameters", json.dumps({"commands": [prefix + "\n" + script], "executionTimeout": [str(args.timeout)]}),
        "--timeout-seconds", "600", "--comment", "Bower lab " + state["runId"] + " " + args.script.name)
    record = {"commandId": response["Command"]["CommandId"], "instanceId": instance_id, "host": args.host,
              "script": args.script.name, "sha256": hashlib.sha256(args.script.read_bytes()).hexdigest()}
    with (args.state.parent / "commands.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
