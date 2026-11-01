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
import re
import subprocess
import sys

ACCOUNT, REGION, PROFILE = "959038055523", "ap-southeast-2", "homelab-admin"
SUBSCRIPTION = "945092a0-2500-4b25-85a4-99f1c3135906"


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    return result.returncode, result.stdout, result.stderr


def aws(*args):
    code, out, err = run(["aws", "--profile", PROFILE, "--region", REGION, "--output", "json", *args])
    return code, (json.loads(out) if code == 0 and out.strip() else None), err


def az(*args):
    code, out, err = run(["az", *args, "--only-show-errors", "--output", "json"])
    return code, (json.loads(out) if code == 0 and out.strip() else None), err


def error_code(err):
    """The service error code only (never the message, which can echo request data)."""
    match = re.search(r"An error occurred \(([A-Za-z0-9.]+)\)", err) or re.search(r"\b(Request_[A-Za-z]+|[A-Za-z]*NotFound[A-Za-z]*)\b", err)
    return match.group(1) if match else "unclassified"


def gone(code, err, *not_found):
    """True only when the call failed with one of the exact not-found codes. Throttling,
    AccessDenied, an expired token or any other failure is not proof of absence."""
    return code != 0 and error_code(err) in not_found


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

    def check(name, absent, code=0, err=""):
        item = {"check": name, "absent": absent}
        if code != 0:
            item["errorCode"] = error_code(err)
        checks.append(item)

    def exact(name, result, *not_found):
        code, _, err = result
        check(name, gone(code, err, *not_found), code, err)

    def listing(name, result, empty):
        code, data, err = result
        check(name, code == 0 and empty(data), code, err)

    code, identity, _ = aws("sts", "get-caller-identity")
    if code or identity["Account"] != ACCOUNT:
        raise SystemExit("unexpected AWS account")
    resources = json.loads(args.stack_resources.read_text())
    code, stacks, err = aws("cloudformation", "describe-stacks", "--stack-name", run_id)
    deleted_stack = code == 0 and all(stack["StackStatus"] == "DELETE_COMPLETE" for stack in stacks["Stacks"])
    missing_stack = code != 0 and error_code(err) == "ValidationError" and "does not exist" in err
    check("cloudformation stack " + run_id, deleted_stack or missing_stack, 0 if deleted_stack or missing_stack else code, err)
    for resource in resources:
        kind, physical = resource["type"], resource["physical"]
        if kind == "AWS::EC2::Instance":
            code, data, err = aws("ec2", "describe-instances", "--instance-ids", physical)
            if code == 0:
                states = {item["State"]["Name"] for reservation in data["Reservations"] for item in reservation["Instances"]}
                check("instance " + physical + " (" + ",".join(sorted(states)) + ")", states <= {"terminated"})
            else:
                check("instance " + physical, gone(code, err, "InvalidInstanceID.NotFound"), code, err)
        elif kind == "AWS::EC2::SecurityGroup":
            exact("security group " + physical, aws("ec2", "describe-security-groups", "--group-ids", physical),
                  "InvalidGroup.NotFound")
        elif kind == "AWS::EC2::Subnet":
            exact("subnet " + physical, aws("ec2", "describe-subnets", "--subnet-ids", physical), "InvalidSubnetID.NotFound")
        elif kind == "AWS::EC2::RouteTable":
            exact("route table " + physical, aws("ec2", "describe-route-tables", "--route-table-ids", physical),
                  "InvalidRouteTableID.NotFound")
        elif kind == "AWS::IAM::Role":
            exact("IAM role " + physical, aws("iam", "get-role", "--role-name", physical), "NoSuchEntity")
        elif kind == "AWS::IAM::InstanceProfile":
            exact("instance profile " + physical, aws("iam", "get-instance-profile", "--instance-profile-name", physical),
                  "NoSuchEntity")
        elif kind == "AWS::S3::Bucket":
            # head-bucket reports a missing bucket as HTTP 404; 403 means it exists for someone else.
            exact("S3 bucket " + physical, aws("s3api", "head-bucket", "--bucket", physical), "404", "NoSuchBucket")
        elif kind == "AWS::Scheduler::Schedule":
            exact("expiry schedule " + physical, aws("scheduler", "get-schedule", "--name", physical),
                  "ResourceNotFoundException")
    for volume in json.loads(args.volumes.read_text()):
        exact("EBS volume " + volume, aws("ec2", "describe-volumes", "--volume-ids", volume), "InvalidVolume.NotFound")
    listing("EBS snapshots tagged RunId", aws("ec2", "describe-snapshots", "--owner-ids", "self", "--filters",
                                              "Name=tag:RunId,Values=" + run_id), lambda data: not data["Snapshots"])
    listing("CloudWatch log groups with the run prefix", aws("logs", "describe-log-groups", "--log-group-name-prefix",
                                                               "/" + run_id), lambda data: not data["logGroups"])
    listing("Secrets Manager secrets tagged RunId", aws("secretsmanager", "list-secrets", "--filters",
                                                        "Key=tag-value,Values=" + run_id), lambda data: not data["SecretList"])
    code, tagged, err = aws("resourcegroupstaggingapi", "get-resources", "--tag-filters", "Key=RunId,Values=" + run_id)
    remaining = [item["ResourceARN"] for item in (tagged or {}).get("ResourceTagMappingList", [])]

    def confirmed_gone(arn):
        # The tagging API keeps deleted EC2 resources listed for a while: re-check each one
        # with its own describe call; anything not confirmed gone stays a failure.
        resource = arn.rsplit("/", 1)[-1]
        if ":instance/" in arn:
            status, data, error = aws("ec2", "describe-instances", "--instance-ids", resource)
            if status == 0:
                return {item["State"]["Name"] for reservation in data["Reservations"]
                        for item in reservation["Instances"]} <= {"terminated"}
            return gone(status, error, "InvalidInstanceID.NotFound")
        if ":volume/" in arn:
            status, _, error = aws("ec2", "describe-volumes", "--volume-ids", resource)
            return gone(status, error, "InvalidVolume.NotFound")
        return False

    live = [arn for arn in remaining if not confirmed_gone(arn)]
    item = {"check": "AWS resources tagged RunId (tagging API, region; listed ARNs re-verified)",
            "absent": code == 0 and not live, "listedByTaggingApi": remaining, "notConfirmedGone": live}
    if code:
        item["errorCode"] = error_code(err)
    checks.append(item)

    state = json.loads(args.azure_state.read_text())
    group, workspace = state["group"], state["workspaceName"]
    listing("Azure resource group " + group, az("group", "exists", "--name", group, "--subscription", SUBSCRIPTION),
            lambda data: data is False)
    listing("Azure resources tagged RunId", az("resource", "list", "--tag", "RunId=" + run_id, "--subscription",
                                               SUBSCRIPTION), lambda data: not data)
    listing("soft-deleted workspace " + workspace,
            az("monitor", "log-analytics", "workspace", "list-deleted-workspaces", "--subscription", SUBSCRIPTION),
            lambda data: not [item for item in data or [] if item.get("name") == workspace])
    for role in ("ingest", "verifier"):
        identity = state["identities"][role]
        listing("Entra application " + identity["name"], az("ad", "app", "list", "--display-name", identity["name"]),
                lambda data: not data)
        listing("service principal of " + identity["name"],
                az("ad", "sp", "list", "--display-name", identity["name"]),
                lambda data: not [item for item in data or [] if item.get("displayName") == identity["name"]])
        for kind, object_id in (("application", identity.get("objectId")), ("service principal", identity.get("principalId"))):
            if object_id:
                # Only Graph's not-found proves the soft-deleted object was purged.
                exact("deleted-items " + kind + " " + object_id,
                      az("rest", "--method", "get", "--url", "https://graph.microsoft.com/v1.0/directory/deletedItems/" + object_id),
                      "Request_ResourceNotFound")
        if identity.get("principalId"):
            listing("role assignments of " + identity["name"],
                    az("role", "assignment", "list", "--all", "--assignee-object-id", identity["principalId"],
                       "--subscription", SUBSCRIPTION), lambda data: not data)

    result = {"schemaVersion": 1, "runId": run_id, "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
              "accountId": ACCOUNT, "region": REGION, "azureSubscription": SUBSCRIPTION,
              "checks": checks, "allAbsent": all(item["absent"] for item in checks)}
    args.output.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({"checks": len(checks), "allAbsent": result["allAbsent"],
                      "remaining": [item["check"] for item in checks if not item["absent"]]}))
    return 0 if result["allAbsent"] else 1


if __name__ == "__main__":
    sys.exit(main())
