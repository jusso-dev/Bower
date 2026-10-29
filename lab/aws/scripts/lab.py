"""Plan/apply/inspect/tear down one disposable lab, with account and tag guards."""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess


def aws(profile, region, *args):
    command = ["aws", "--profile", profile, "--region", region, *args, "--output", "json"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else {}


def verify_account(profile, region, expected):
    identity = aws(profile, region, "sts", "get-caller-identity")
    if identity["Account"] != expected:
        raise ValueError("AWS account mismatch; refusing lab operation")


def verify_stack(stack, run_id):
    tags = {t["Key"]: t["Value"] for t in stack.get("Tags", [])}
    if tags.get("Project") != "bower-lab" or tags.get("RunId") != run_id:
        raise ValueError("Stack does not belong to this lab run; refusing operation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "status", "destroy"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--profile", default="homelab-admin")
    parser.add_argument("--region", default="ap-southeast-2", choices=("ap-southeast-2",))
    parser.add_argument("--account", default="959038055523")
    parser.add_argument("--hours", type=int, default=8, choices=range(1, 13))
    args = parser.parse_args()
    verify_account(args.profile, args.region, args.account)
    call = lambda *params: aws(args.profile, args.region, *params)
    if args.action == "plan":
        if args.state.exists():
            raise ValueError("State file exists; inspect or destroy its run before making a new plan")
        from template import template
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        expiry = (datetime.now(timezone.utc) + timedelta(hours=args.hours)).strftime("%Y-%m-%dT%H:%M:%S")
        directory = args.state.parent
        directory.mkdir(parents=True, exist_ok=True)
        template_path = directory / (run_id + "-template.json")
        template_path.write_text(json.dumps(template(), indent=1) + "\n", encoding="utf-8")
        call("cloudformation", "validate-template", "--template-body", "file://" + str(template_path.resolve()))
        linux = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        windows = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Core-Base"
        images = {p["Name"]: p["Value"] for p in call("ssm", "get-parameters", "--names", linux, windows)["Parameters"]}
        zones = call("ec2", "describe-availability-zones", "--filters", "Name=state,Values=available")["AvailabilityZones"]
        values = {"RunId": run_id, "Expiry": expiry, "AvailabilityZone": zones[0]["ZoneName"],
                  "LinuxImage": images[linux], "WindowsImage": images[windows], "WindowsType": "t3.micro"}
        params = [{"ParameterKey": key, "ParameterValue": value} for key, value in values.items()]
        stack = "bower-lab-" + run_id
        state = {"runId": run_id, "stack": stack, "account": args.account, "region": args.region,
                 "expiry": expiry, "parameters": values, "sentinel": "deferred-by-user"}
        args.state.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        response = call("cloudformation", "create-change-set", "--stack-name", stack,
            "--change-set-name", "reviewed-lab", "--change-set-type", "CREATE", "--capabilities", "CAPABILITY_IAM",
            "--template-body", "file://" + str(template_path.resolve()), "--parameters", json.dumps(params),
            "--tags", json.dumps([{"Key": "Project", "Value": "bower-lab"}, {"Key": "RunId", "Value": run_id},
                                  {"Key": "Owner", "Value": "Bower-test"}, {"Key": "Expiry", "Value": expiry}]))
        state["changeSet"] = response["Id"]
        args.state.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(state, indent=2))
        return
    state = json.loads(args.state.read_text(encoding="utf-8"))
    if state["account"] != args.account or state["region"] != args.region or not re.fullmatch(r"bower-lab-[0-9]{8}-[0-9]{6}", state["stack"]):
        raise ValueError("State/account/region mismatch")
    stack = call("cloudformation", "describe-stacks", "--stack-name", state["stack"])["Stacks"][0]
    # CREATE change-set placeholders do not acquire their tags until execution.
    # Validate the reviewed change set's tags and exact stack ID in that state.
    if stack["StackStatus"] == "REVIEW_IN_PROGRESS":
        planned = call("cloudformation", "describe-change-set", "--change-set-name", state["changeSet"])
        if planned["StackId"] != stack["StackId"]:
            raise ValueError("Change set belongs to a different stack")
        verify_stack(planned, state["runId"])
    else:
        verify_stack(stack, state["runId"])
    if args.action == "apply":
        changes = call("cloudformation", "describe-change-set", "--change-set-name", state["changeSet"])
        if changes["Status"] != "CREATE_COMPLETE" or changes["ExecutionStatus"] != "AVAILABLE":
            raise ValueError("Change set is not ready or has already run")
        if any(c["ResourceChange"]["Action"] != "Add" for c in changes["Changes"]):
            raise ValueError("Initial lab plan may only add resources")
        call("cloudformation", "execute-change-set", "--change-set-name", state["changeSet"])
        print("Lab creation started: " + state["stack"])
    elif args.action == "destroy":
        call("cloudformation", "delete-stack", "--stack-name", state["stack"])
        print("Teardown started; expiring report bucket retained: " + state["stack"])
    else:
        state["stackStatus"] = stack["StackStatus"]
        state["outputs"] = {entry["OutputKey"]: entry["OutputValue"] for entry in stack.get("Outputs", [])}
        args.state.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        reservations = call("ec2", "describe-instances", "--filters", "Name=tag:Project,Values=bower-lab",
            "Name=tag:RunId,Values=" + state["runId"])["Reservations"]
        ids = [i["InstanceId"] for r in reservations for i in r["Instances"]]
        managed = call("ssm", "describe-instance-information", "--filters", json.dumps([{"Key": "InstanceIds", "Values": ids}])) if ids else {}
        print(json.dumps({"stack": state["stack"], "status": stack["StackStatus"], "hosts": ids,
            "ssm": [{"id": i["InstanceId"], "status": i["PingStatus"], "platform": i["PlatformName"]}
                    for i in managed.get("InstanceInformationList", [])]}, indent=2))


if __name__ == "__main__":
    main()
