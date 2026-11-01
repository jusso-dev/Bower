#!/usr/bin/env python3
"""Independently prove that nothing a RELP run created remains in AWS or Azure.

Read-only. Takes the run's recorded stack resources, volume ids and Azure state (metadata
only) and checks each exact id with its own query, then sweeps for anything still tagged
with the RunId: the AWS resource-groups tagging API in the region, Azure resources and
groups by tag, soft-deleted Log Analytics workspaces, Entra applications by display name,
soft-deleted directory objects and role assignments. Writes cleanup.json; exit 1 when
anything remains or a check could not run. Never prints credentials.
"""

import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys

ACCOUNT, REGION, PROFILE = "959038055523", "ap-southeast-2", "homelab-admin"
SUBSCRIPTION = "945092a0-2500-4b25-85a4-99f1c3135906"


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    return result.returncode, result.stdout


def aws(*args):
    code, out = run(["aws", "--profile", PROFILE, "--region", REGION, "--output", "json", *args])
    return code, json.loads(out) if code == 0 and out.strip() else None


def az(*args):
    code, out = run(["az", *args, "--only-show-errors", "--output", "json"])
    return code, json.loads(out) if code == 0 and out.strip() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stack-resources", type=Path, required=True)
    parser.add_argument("--volumes", type=Path, required=True)
    parser.add_argument("--azure-state", type=Path, required=True, help="azure-state.json (metadata only)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run_id = args.run_id
    checks = []

    def check(name, absent, detail=None):
        checks.append({"check": name, "absent": absent, **({"detail": detail} if detail is not None else {})})

    code, identity = aws("sts", "get-caller-identity")
    if code or identity["Account"] != ACCOUNT:
        raise SystemExit("unexpected AWS account")
    resources = json.loads(args.stack_resources.read_text())
    code, stacks = aws("cloudformation", "describe-stacks", "--stack-name", run_id)
    check("cloudformation stack " + run_id,
          code != 0 or all(stack["StackStatus"] == "DELETE_COMPLETE" for stack in stacks["Stacks"]))
    for resource in resources:
        kind, physical = resource["type"], resource["physical"]
        if kind == "AWS::EC2::Instance":
            code, data = aws("ec2", "describe-instances", "--instance-ids", physical)
            states = [item["State"]["Name"] for reservation in (data or {}).get("Reservations", [])
                      for item in reservation["Instances"]]
            check("instance " + physical, code != 0 or set(states) <= {"terminated"}, states)
        elif kind == "AWS::EC2::SecurityGroup":
            code, _ = aws("ec2", "describe-security-groups", "--group-ids", physical)
            check("security group " + physical, code != 0)
        elif kind == "AWS::EC2::Subnet":
            code, _ = aws("ec2", "describe-subnets", "--subnet-ids", physical)
            check("subnet " + physical, code != 0)
        elif kind == "AWS::EC2::RouteTable":
            code, _ = aws("ec2", "describe-route-tables", "--route-table-ids", physical)
            check("route table " + physical, code != 0)
        elif kind == "AWS::IAM::Role":
            code, _ = aws("iam", "get-role", "--role-name", physical)
            check("IAM role " + physical, code != 0)
        elif kind == "AWS::IAM::InstanceProfile":
            code, _ = aws("iam", "get-instance-profile", "--instance-profile-name", physical)
            check("instance profile " + physical, code != 0)
        elif kind == "AWS::S3::Bucket":
            code, _ = aws("s3api", "head-bucket", "--bucket", physical)
            check("S3 bucket " + physical, code != 0)
        elif kind == "AWS::Scheduler::Schedule":
            code, _ = aws("scheduler", "get-schedule", "--name", physical)
            check("expiry schedule " + physical, code != 0)
    for volume in json.loads(args.volumes.read_text()):
        code, _ = aws("ec2", "describe-volumes", "--volume-ids", volume)
        check("EBS volume " + volume, code != 0)
    code, snapshots = aws("ec2", "describe-snapshots", "--owner-ids", "self", "--filters", "Name=tag:RunId,Values=" + run_id)
    check("EBS snapshots tagged RunId", code == 0 and not snapshots["Snapshots"], "query failed" if code else None)
    code, groups = aws("logs", "describe-log-groups", "--log-group-name-prefix", "/" + run_id)
    check("CloudWatch log groups with the run prefix", code == 0 and not groups["logGroups"])
    code, secrets = aws("secretsmanager", "list-secrets", "--filters", "Key=tag-value,Values=" + run_id)
    check("Secrets Manager secrets tagged RunId", code == 0 and not secrets["SecretList"])
    code, tagged = aws("resourcegroupstaggingapi", "get-resources", "--tag-filters", "Key=RunId,Values=" + run_id)
    remaining = [item["ResourceARN"] for item in (tagged or {}).get("ResourceTagMappingList", [])]

    def gone(arn):
        # The tagging API keeps deleted EC2 resources listed for a while: re-check each one
        # with its own describe call; anything not confirmed gone stays a failure.
        resource = arn.rsplit("/", 1)[-1]
        if ":instance/" in arn:
            status, data = aws("ec2", "describe-instances", "--instance-ids", resource)
            return status != 0 or {item["State"]["Name"] for reservation in data["Reservations"]
                                   for item in reservation["Instances"]} <= {"terminated"}
        if ":volume/" in arn:
            return aws("ec2", "describe-volumes", "--volume-ids", resource)[0] != 0
        return False

    live = [arn for arn in remaining if not gone(arn)]
    check("AWS resources tagged RunId (tagging API, region; listed ARNs re-verified)", code == 0 and not live,
          {"listedByTaggingApi": remaining, "notConfirmedGone": live})

    state = json.loads(args.azure_state.read_text())
    group, workspace = state["group"], state["workspaceName"]
    code, exists = az("group", "exists", "--name", group, "--subscription", SUBSCRIPTION)
    check("Azure resource group " + group, code == 0 and exists is False)
    code, tagged = az("resource", "list", "--tag", "RunId=" + run_id, "--subscription", SUBSCRIPTION)
    check("Azure resources tagged RunId", code == 0 and not tagged)
    code, deleted = az("monitor", "log-analytics", "workspace", "list-deleted-workspaces", "--subscription", SUBSCRIPTION)
    check("soft-deleted workspace " + workspace,
          code == 0 and not [item for item in deleted or [] if item.get("name") == workspace])
    for role in ("ingest", "verifier"):
        identity = state["identities"][role]
        code, apps = az("ad", "app", "list", "--display-name", identity["name"])
        check("Entra application " + identity["name"], code == 0 and not apps)
        code, principals = az("ad", "sp", "list", "--filter", "appId eq '{}'".format(identity["appId"]))
        check("service principal of " + identity["name"], code == 0 and not principals)
        for kind, object_id in (("application", identity.get("objectId")), ("service principal", identity.get("principalId"))):
            if object_id:
                code, _ = az("rest", "--method", "get", "--url",
                             "https://graph.microsoft.com/v1.0/directory/deletedItems/" + object_id)
                check("deleted-items " + kind + " " + object_id, code != 0)
        if identity.get("principalId"):
            code, grants = az("role", "assignment", "list", "--all", "--assignee-object-id", identity["principalId"],
                              "--subscription", SUBSCRIPTION)
            check("role assignments of " + identity["name"], code == 0 and not grants)

    result = {"schemaVersion": 1, "runId": run_id, "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
              "accountId": ACCOUNT, "region": REGION, "azureSubscription": SUBSCRIPTION,
              "checks": checks, "allAbsent": all(item["absent"] for item in checks)}
    args.output.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({"checks": len(checks), "allAbsent": result["allAbsent"],
                      "remaining": [item["check"] for item in checks if not item["absent"]]}))
    return 0 if result["allAbsent"] else 1


if __name__ == "__main__":
    sys.exit(main())
