#!/usr/bin/env python3
"""Tear down a storage-pressure lab run and independently prove nothing remains.

teardown: records the stack's resources and volume ids, deletes the stack, the artifact
bucket and the run's Secrets Manager secrets, force-deletes the Log Analytics workspace,
deletes the Azure resource group and both Entra applications, and purges them from
Entra deleted items. Only resources named or tagged for this run are touched.

audit (read-only): checks each recorded id with its own query and sweeps for anything
still tagged with the RunId. Absence counts only when a call fails with the exact
not-found code; throttling, AccessDenied or any other error is not proof. Writes
cleanup.json and exits 1 when anything remains or a check could not run. Never prints
credentials.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ACCOUNT, REGION, PROFILE = "959038055523", "ap-southeast-2", "homelab-admin"
SUBSCRIPTION = "945092a0-2500-4b25-85a4-99f1c3135906"
RUN_PATTERN = r"bower-ws3b?-\d{8}-\d{6}"


def run(argv, timeout=900):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def aws(*args):
    code, out, err = run(["aws", "--profile", PROFILE, "--region", REGION, "--output", "json", *args])
    return code, (json.loads(out) if code == 0 and out.strip() else None), err


def az(*args):
    code, out, err = run(["az", *args, "--only-show-errors", "--output", "json"])
    return code, (json.loads(out) if code == 0 and out.strip() else None), err


def error_code(err):
    """The service error code only (never the message, which can echo request data)."""
    match = (re.search(r"An error occurred \(([A-Za-z0-9.]+)\)", err)
             or re.search(r"\b(Request_[A-Za-z]+|[A-Za-z]*NotFound[A-Za-z]*|StateMachineDoesNotExist)\b", err))
    return match.group(1) if match else "unclassified"


def gone(code, err, *not_found):
    return code != 0 and error_code(err) in not_found


def verify_account():
    code, identity, _ = aws("sts", "get-caller-identity")
    if code or identity["Account"] != ACCOUNT:
        raise SystemExit("unexpected AWS account")


def teardown(state, azure, out):
    run_id = state["runId"]
    verify_account()
    code, stacks, err = aws("cloudformation", "describe-stacks", "--stack-name", run_id)
    if code == 0:
        tags = {tag["Key"]: tag["Value"] for tag in stacks["Stacks"][0].get("Tags", [])}
        if tags.get("Project") != "bower-lab" or tags.get("RunId") != run_id:
            raise SystemExit("refusing: stack is not tagged for this run")
        _, listed, _ = aws("cloudformation", "list-stack-resources", "--stack-name", run_id)
        resources = [{"type": item["ResourceType"], "logical": item["LogicalResourceId"],
                      "physical": item.get("PhysicalResourceId", "")} for item in listed["StackResourceSummaries"]]
        (out / "stack-resources.json").write_text(json.dumps(resources, indent=1) + "\n")
        volumes = []
        for item in resources:
            if item["type"] == "AWS::EC2::Instance":
                _, data, _ = aws("ec2", "describe-instances", "--instance-ids", item["physical"])
                for reservation in data["Reservations"]:
                    for instance in reservation["Instances"]:
                        volumes += [mapping["Ebs"]["VolumeId"] for mapping in instance.get("BlockDeviceMappings", [])]
        (out / "volumes.json").write_text(json.dumps(sorted(volumes), indent=1) + "\n")
        aws("cloudformation", "delete-stack", "--stack-name", run_id)
        aws("cloudformation", "wait", "stack-delete-complete", "--stack-name", run_id)
    bucket = state["bucket"]
    code, tagging, _ = aws("s3api", "get-bucket-tagging", "--bucket", bucket)
    if code == 0 and {"Key": "RunId", "Value": run_id} in tagging["TagSet"]:
        run(["aws", "--profile", PROFILE, "--region", REGION, "s3", "rm", f"s3://{bucket}", "--recursive", "--quiet"])
        aws("s3api", "delete-bucket", "--bucket", bucket)
    _, secrets, _ = aws("secretsmanager", "list-secrets", "--filters", "Key=tag-value,Values=" + run_id)
    for secret in (secrets or {}).get("SecretList", []):
        tags = {tag["Key"]: tag["Value"] for tag in secret.get("Tags", [])}
        if tags.get("RunId") == run_id and secret["Name"].startswith(f"bower-lab/{run_id}/"):
            aws("secretsmanager", "delete-secret", "--secret-id", secret["ARN"], "--force-delete-without-recovery")

    group, workspace = azure["group"], azure["workspaceName"]
    code, exists, _ = az("group", "exists", "--name", group, "--subscription", SUBSCRIPTION)
    if exists:
        az("monitor", "log-analytics", "workspace", "delete", "--resource-group", group, "--workspace-name", workspace,
           "--force", "true", "--yes", "--subscription", SUBSCRIPTION)
        az("group", "delete", "--name", group, "--yes", "--subscription", SUBSCRIPTION)
    for identity in azure["identities"].values():
        if not identity["name"].startswith(run_id + "-"):
            raise SystemExit("refusing: identity is not named for this run")
        az("ad", "app", "delete", "--id", identity["appId"])
    time.sleep(20)
    for identity in azure["identities"].values():
        for object_id in (identity.get("objectId"), identity.get("principalId")):
            if object_id:
                az("rest", "--method", "delete", "--url", "https://graph.microsoft.com/v1.0/directory/deletedItems/" + object_id)


def audit(state, azure, out):
    run_id = state["runId"]
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

    verify_account()
    code, stacks, err = aws("cloudformation", "describe-stacks", "--stack-name", run_id)
    deleted = code == 0 and all(stack["StackStatus"] == "DELETE_COMPLETE" for stack in stacks["Stacks"])
    missing = code != 0 and error_code(err) == "ValidationError" and "does not exist" in err
    check("cloudformation stack " + run_id, deleted or missing, 0 if deleted or missing else code, err)
    resources_file = out / "stack-resources.json"
    resources = json.loads(resources_file.read_text()) if resources_file.exists() else []
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
            exact("security group " + physical, aws("ec2", "describe-security-groups", "--group-ids", physical), "InvalidGroup.NotFound")
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
        elif kind == "AWS::StepFunctions::StateMachine":
            exact("expiry state machine " + physical.rsplit(":", 1)[-1],
                  aws("stepfunctions", "describe-state-machine", "--state-machine-arn", physical), "StateMachineDoesNotExist")
        elif kind == "AWS::Scheduler::Schedule":
            exact("expiry schedule " + physical, aws("scheduler", "get-schedule", "--name", physical), "ResourceNotFoundException")
    volumes_file = out / "volumes.json"
    for volume in json.loads(volumes_file.read_text()) if volumes_file.exists() else []:
        exact("EBS volume " + volume, aws("ec2", "describe-volumes", "--volume-ids", volume), "InvalidVolume.NotFound")
    exact("S3 bucket " + state["bucket"], aws("s3api", "head-bucket", "--bucket", state["bucket"]), "404", "NoSuchBucket")
    listing("EBS snapshots tagged RunId", aws("ec2", "describe-snapshots", "--owner-ids", "self", "--filters",
                                              "Name=tag:RunId,Values=" + run_id), lambda data: not data["Snapshots"])
    listing("Secrets Manager secrets tagged RunId", aws("secretsmanager", "list-secrets", "--include-planned-deletion",
                                                        "--filters", "Key=tag-value,Values=" + run_id),
            lambda data: not data["SecretList"])
    listing("CloudWatch log groups with the run prefix", aws("logs", "describe-log-groups", "--log-group-name-prefix",
                                                               "/" + run_id), lambda data: not data["logGroups"])
    code, tagged, err = aws("resourcegroupstaggingapi", "get-resources", "--tag-filters", "Key=RunId,Values=" + run_id)
    remaining = [item["ResourceARN"] for item in (tagged or {}).get("ResourceTagMappingList", [])]

    def confirmed_gone(arn):
        # The tagging API keeps deleted resources listed for a while: re-check each one.
        resource = arn.rsplit("/", 1)[-1]
        if ":instance/" in arn:
            status, data, error = aws("ec2", "describe-instances", "--instance-ids", resource)
            if status == 0:
                return {item["State"]["Name"] for reservation in data["Reservations"] for item in reservation["Instances"]} <= {"terminated"}
            return gone(status, error, "InvalidInstanceID.NotFound")
        if ":volume/" in arn:
            status, _, error = aws("ec2", "describe-volumes", "--volume-ids", resource)
            return gone(status, error, "InvalidVolume.NotFound")
        if ":subnet/" in arn:
            status, _, error = aws("ec2", "describe-subnets", "--subnet-ids", resource)
            return gone(status, error, "InvalidSubnetID.NotFound")
        if ":security-group/" in arn:
            status, _, error = aws("ec2", "describe-security-groups", "--group-ids", resource)
            return gone(status, error, "InvalidGroup.NotFound")
        if ":route-table/" in arn:
            status, _, error = aws("ec2", "describe-route-tables", "--route-table-ids", resource)
            return gone(status, error, "InvalidRouteTableID.NotFound")
        if ":secret:" in arn:
            status, _, error = aws("secretsmanager", "describe-secret", "--secret-id", arn)
            return gone(status, error, "ResourceNotFoundException")
        if ":stateMachine:" in arn:
            status, _, error = aws("stepfunctions", "describe-state-machine", "--state-machine-arn", arn)
            return gone(status, error, "StateMachineDoesNotExist")
        return False

    live = [arn for arn in remaining if not confirmed_gone(arn)]
    item = {"check": "AWS resources tagged RunId (tagging API, region; listed ARNs re-verified)",
            "absent": code == 0 and not live, "listedByTaggingApi": remaining, "notConfirmedGone": live}
    if code:
        item["errorCode"] = error_code(err)
    checks.append(item)

    group, workspace = azure["group"], azure["workspaceName"]
    listing("Azure resource group " + group, az("group", "exists", "--name", group, "--subscription", SUBSCRIPTION),
            lambda data: data is False)
    listing("Azure resources tagged RunId", az("resource", "list", "--tag", "RunId=" + run_id, "--subscription", SUBSCRIPTION),
            lambda data: not data)
    listing("soft-deleted workspace " + workspace,
            az("monitor", "log-analytics", "workspace", "list-deleted-workspaces", "--subscription", SUBSCRIPTION),
            lambda data: not [item for item in data or [] if item.get("name") == workspace])
    for identity in azure["identities"].values():
        name = identity["name"]
        listing("Entra application " + name, az("ad", "app", "list", "--display-name", name), lambda data: not data)
        listing("service principal of " + name, az("ad", "sp", "list", "--display-name", name),
                lambda data: not [item for item in data or [] if item.get("displayName") == name])
        for kind, object_id in (("application", identity.get("objectId")), ("service principal", identity.get("principalId"))):
            if object_id:
                exact("deleted-items " + kind + " " + object_id,
                      az("rest", "--method", "get", "--url", "https://graph.microsoft.com/v1.0/directory/deletedItems/" + object_id),
                      "Request_ResourceNotFound")
        if identity.get("principalId"):
            listing("role assignments of " + name,
                    az("role", "assignment", "list", "--all", "--assignee-object-id", identity["principalId"],
                       "--subscription", SUBSCRIPTION), lambda data: not data)

    result = {"schemaVersion": 1, "runId": run_id, "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
              "accountId": ACCOUNT, "region": REGION, "azureSubscription": SUBSCRIPTION,
              "checks": checks, "allAbsent": all(item["absent"] for item in checks)}
    (out / "cleanup.json").write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({"checks": len(checks), "allAbsent": result["allAbsent"],
                      "remaining": [item["check"] for item in checks if not item["absent"]]}))
    return 0 if result["allAbsent"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["teardown", "audit"])
    parser.add_argument("--state", type=Path, required=True, help="storage-lab state.json")
    parser.add_argument("--azure-state", type=Path, required=True, help="azure-state.json (names and ids only)")
    parser.add_argument("--output", type=Path, required=True, help="directory for metadata files")
    args = parser.parse_args()
    state = json.loads(args.state.read_text())
    azure = json.loads(args.azure_state.read_text())
    if not re.fullmatch(RUN_PATTERN, state["runId"]) or azure["group"] != "rg-" + state["runId"]:
        raise SystemExit("refusing: unexpected run id or resource group")
    args.output.mkdir(parents=True, exist_ok=True)
    if args.command == "teardown":
        teardown(state, azure, args.output)
        return 0
    return audit(state, azure, args.output)


if __name__ == "__main__":
    sys.exit(main())
