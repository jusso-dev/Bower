#!/usr/bin/env python3
"""Disposable syslog delivery-reliability lab: two collectors, two senders, SSM only.

Plan, apply, run guarded SSM scripts, tear down and audit one run. Every mutation is
scoped to the run's own stack, tagged Project=bower-lab and RunId=<run id>. The lab
uses a private subnet of its own in the default VPC and routes egress through an
existing NAT gateway passed explicitly; it never modifies that gateway.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

ACCOUNT = "959038055523"
REGION = "ap-southeast-2"
PROFILE = "homelab-admin"
RUN_PATTERN = r"bower-[a-z0-9]{2,8}-[0-9]{8}-[0-9]{6}"
HOSTS = {"CollectorA": "t3.small", "CollectorB": "t3.micro", "SenderR": "t3.micro", "SenderG": "t3.small"}
SENDERS = ("SenderR", "SenderG")
COLLECTORS = ("CollectorA", "CollectorB")
SYSLOG_PORTS = (6514, 6516)


class AwsCliError(RuntimeError):
    def __init__(self, invocation_not_found=False, volume_not_found=False):
        super().__init__("AWS CLI request failed")
        self.invocation_not_found = invocation_not_found
        self.volume_not_found = volume_not_found


def run_aws(command, timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 1800:
        raise ValueError("AWS CLI timeout must be positive and bounded")
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise TimeoutError("AWS CLI request timed out") from None
    except subprocess.CalledProcessError as error:
        stderr = str(error.stderr or "")
        match = re.search(r"An error occurred \(([^)]+)\) when calling\b", stderr)
        code = match.group(1) if match else ""
        raise AwsCliError(code == "InvocationDoesNotExist", code == "InvalidVolume.NotFound") from None
    except OSError:
        raise AwsCliError() from None


def aws(*args, profile=PROFILE, region=REGION, timeout=120):
    command = ["aws", "--profile", profile, "--region", region, *args, "--output", "json"]
    result = run_aws(command, timeout)
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        raise RuntimeError("AWS CLI returned invalid JSON") from None


def aws_wait_or_remove(*args):
    # S3 cleanup and CloudFormation waiters may take longer than read-only calls,
    # but must still terminate. Output and errors stay metadata-only.
    return run_aws(["aws", "--profile", PROFILE, "--region", REGION, *args], 1800)


def verify_account():
    if aws("sts", "get-caller-identity")["Account"] != ACCOUNT:
        raise ValueError("AWS account mismatch; refusing lab operation")


def owned(resource_tags, run_id):
    tags = {t["Key"]: t["Value"] for t in resource_tags or []}
    return tags.get("Project") == "bower-lab" and tags.get("RunId") == run_id


def template():
    resources = {}

    def ref(name):
        return {"Ref": name}

    def sub(value):
        return {"Fn::Sub": value}

    def attr(name, field):
        return {"Fn::GetAtt": [name, field]}

    def tags(role):
        return [{"Key": k, "Value": v} for k, v in {"Project": "bower-lab", "RunId": ref("RunId"),
                "Owner": "Bower-test", "Expiry": ref("Expiry"), "Role": role}.items()]

    def add(name, kind, properties, **extra):
        resources[name] = {"Type": "AWS::" + kind, "Properties": properties, **extra}
        return ref(name)

    subnet = add("Subnet", "EC2::Subnet", {"VpcId": ref("VpcId"), "CidrBlock": ref("SubnetCidr"),
        "AvailabilityZone": ref("AvailabilityZone"), "MapPublicIpOnLaunch": False, "Tags": tags("private")})
    routes = add("Routes", "EC2::RouteTable", {"VpcId": ref("VpcId"), "Tags": tags("private")})
    add("RouteAssociation", "EC2::SubnetRouteTableAssociation", {"SubnetId": subnet, "RouteTableId": routes})
    add("DefaultRoute", "EC2::Route", {"RouteTableId": routes, "DestinationCidrBlock": "0.0.0.0/0",
        "NatGatewayId": ref("NatGatewayId")})
    bucket = add("Artifacts", "S3::Bucket", {
        "BucketEncryption": {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        "PublicAccessBlockConfiguration": {k: True for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")},
        "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
        "LifecycleConfiguration": {"Rules": [{"Id": "expire", "Status": "Enabled", "ExpirationInDays": 2}]},
        "Tags": tags("artifacts")})
    add("BucketPolicy", "S3::BucketPolicy", {"Bucket": bucket, "PolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": [attr("Artifacts", "Arn"), sub("${Artifacts.Arn}/*")],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}})
    https = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"}]
    collectors = add("CollectorGroup", "EC2::SecurityGroup", {"GroupDescription": "Syslog collectors: TLS syslog from lab senders only",
        "VpcId": ref("VpcId"), "SecurityGroupEgress": https, "Tags": tags("collector")})
    senders = add("SenderGroup", "EC2::SecurityGroup", {"GroupDescription": "Syslog senders: no inbound",
        "VpcId": ref("VpcId"), "SecurityGroupEgress": https, "Tags": tags("sender")})
    add("SyslogIngress", "EC2::SecurityGroupIngress", {"GroupId": collectors, "IpProtocol": "tcp",
        "FromPort": SYSLOG_PORTS[0], "ToPort": SYSLOG_PORTS[1], "SourceSecurityGroupId": senders})
    # Optional return path: lets the collector's TCP resets reach senders after security-group
    # connection tracking has forgotten a closed flow (see docs/production-readiness/01).
    resources["CollectorReturnPath"] = {"Type": "AWS::EC2::SecurityGroupEgress", "Condition": "ReturnPath",
        "Properties": {"GroupId": collectors, "IpProtocol": "tcp", "FromPort": 1024, "ToPort": 65535,
                       "DestinationSecurityGroupId": senders,
                       "Description": "TCP resets from syslog listeners back to sender ephemeral ports"}}
    add("SyslogEgress", "EC2::SecurityGroupEgress", {"GroupId": senders, "IpProtocol": "tcp",
        "FromPort": SYSLOG_PORTS[0], "ToPort": SYSLOG_PORTS[1], "DestinationSecurityGroupId": collectors})
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role = add("HostRole", "IAM::Role", {"AssumeRolePolicyDocument": trust,
        "ManagedPolicyArns": [sub("arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore")],
        "Policies": [{"PolicyName": "LabArtifacts", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": sub("${Artifacts.Arn}/artifacts/*")},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": sub("${Artifacts.Arn}/exchange/*")},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": sub("${Artifacts.Arn}/results/*")}]}}],
        "Tags": tags("host")})
    add("HostProfile", "IAM::InstanceProfile", {"Roles": [role]})
    outputs = {"Bucket": {"Value": bucket}, "SubnetId": {"Value": subnet}}
    for name, size in HOSTS.items():
        add(name, "EC2::Instance", {"ImageId": ref("LinuxImage"), "InstanceType": size, "SubnetId": subnet,
            "SecurityGroupIds": [collectors if name in COLLECTORS else senders], "IamInstanceProfile": ref("HostProfile"),
            "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1},
            "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 10, "VolumeType": "gp3",
                "Encrypted": True, "DeleteOnTermination": True}}],
            "Tags": tags(name.lower()) + [{"Key": "Name", "Value": sub("${RunId}-" + name.lower())}]},
            DependsOn=["DefaultRoute", "RouteAssociation"])
        outputs[name + "Id"] = {"Value": ref(name)}
        outputs[name + "Ip"] = {"Value": attr(name, "PrivateIp")}
    # Independent expiry guard: terminates only this run's instances if teardown never happens.
    instances = [sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${" + n + "}") for n in HOSTS]
    add("ExpiryWorkerRole", "IAM::Role", {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole",
         "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}}]},
        "Policies": [{"PolicyName": "TerminateOnlyThisLab", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "ec2:TerminateInstances", "Resource": instances}]}}], "Tags": tags("expiry")})
    add("ExpiryWorker", "StepFunctions::StateMachine", {"RoleArn": attr("ExpiryWorkerRole", "Arn"),
        "Definition": {"StartAt": "Terminate", "States": {"Terminate": {"Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:ec2:terminateInstances",
            "Parameters": {"InstanceIds": [ref(n) for n in HOSTS]}, "End": True}}}, "Tags": tags("expiry")})
    add("ExpiryRole", "IAM::Role", {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole",
         "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}}]},
        "Policies": [{"PolicyName": "ExpireOnlyThisLab", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "states:StartExecution", "Resource": ref("ExpiryWorker")}]}}], "Tags": tags("expiry")})
    add("ExpirySchedule", "Scheduler::Schedule", {"ScheduleExpression": sub("at(${Expiry})"),
        "ScheduleExpressionTimezone": "UTC", "FlexibleTimeWindow": {"Mode": "OFF"},
        "Target": {"Arn": ref("ExpiryWorker"), "RoleArn": attr("ExpiryRole", "Arn"), "Input": "{}"}})
    return {"AWSTemplateFormatVersion": "2010-09-09",
            "Description": "Disposable Bower syslog delivery-reliability lab; private hosts, SSM only",
            "Parameters": {"RunId": {"Type": "String", "AllowedPattern": RUN_PATTERN},
                           "Expiry": {"Type": "String", "AllowedPattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"},
                           "VpcId": {"Type": "AWS::EC2::VPC::Id"}, "NatGatewayId": {"Type": "String", "AllowedPattern": "nat-[0-9a-f]+"},
                           "SubnetCidr": {"Type": "String"}, "AvailabilityZone": {"Type": "AWS::EC2::AvailabilityZone::Name"},
                           "LinuxImage": {"Type": "AWS::EC2::Image::Id"},
                           "ReturnPath": {"Type": "String", "AllowedValues": ["true", "false"], "Default": "false"}},
            "Conditions": {"ReturnPath": {"Fn::Equals": [{"Ref": "ReturnPath"}, "true"]}},
            "Resources": resources, "Outputs": outputs}


def load_state(path):
    state = json.loads(path.read_text(encoding="utf-8"))
    if not re.fullmatch(RUN_PATTERN, state["runId"]) or state["stack"] != state["runId"]:
        raise ValueError("Unexpected state file")
    return state


def save_state(path, state):
    path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def verify_stack(state):
    stack = aws("cloudformation", "describe-stacks", "--stack-name", state["stack"])["Stacks"][0]
    if stack["StackStatus"] == "REVIEW_IN_PROGRESS":
        planned = aws("cloudformation", "describe-change-set", "--change-set-name", state["changeSet"])
        if planned["StackId"] != stack["StackId"] or not owned(planned.get("Tags"), state["runId"]):
            raise ValueError("Change set does not belong to this run")
    elif not owned(stack.get("Tags"), state["runId"]):
        raise ValueError("Stack does not belong to this run")
    return stack


def verify_host(state, host):
    """Exact instance ID from the run's stack outputs, with ownership tags and running state."""
    instance_id = state["outputs"][host + "Id"]
    instance = aws("ec2", "describe-instances", "--instance-ids", instance_id)["Reservations"][0]["Instances"][0]
    if not owned(instance.get("Tags"), state["runId"]) or instance["State"]["Name"] != "running":
        raise ValueError(host + " is not a running instance of this run")
    return instance_id


def valid_volume_inventory(state):
    ids = [state.get("outputs", {}).get(host + "Id") for host in HOSTS]
    if not all(isinstance(item, str) and re.fullmatch(r"i-[0-9a-f]{8,17}", item) for item in ids) or len(set(ids)) != len(HOSTS):
        return False
    inventory = state.get("volumeInventory")
    if not isinstance(inventory, dict) or set(inventory) != set(ids):
        return False
    volumes = []
    for instance_id in ids:
        entries = inventory[instance_id]
        if not isinstance(entries, list) or not entries:
            return False
        if not all(isinstance(value, str) and re.fullmatch(r"vol-[0-9a-f]{8,17}", value) for value in entries):
            return False
        volumes.extend(entries)
    return len(set(volumes)) == len(volumes)


def capture_volume_inventory(state, stack):
    """Capture EBS mappings from each verified live stack instance before teardown."""
    outputs = {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}
    previous = state.get("volumeInventory")
    if previous is not None and not valid_volume_inventory(state):
        raise ValueError("Existing volume inventory is incomplete or invalid")
    captured = {}
    for host in HOSTS:
        instance_id = state.get("outputs", {}).get(host + "Id")
        if not isinstance(instance_id, str) or not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id) or outputs.get(host + "Id") != instance_id:
            raise ValueError("Instance inventory does not match the live stack")
        instance = aws("ec2", "describe-instances", "--instance-ids", instance_id)["Reservations"][0]["Instances"][0]
        if instance.get("InstanceId") != instance_id or not owned(instance.get("Tags"), state["runId"]):
            raise ValueError("Instance does not belong to this run")
        mappings = instance.get("BlockDeviceMappings", [])
        root = instance.get("RootDeviceName")
        observed = [entry.get("Ebs", {}).get("VolumeId") for entry in mappings if "Ebs" in entry]
        root_present = isinstance(root, str) and bool(root) and any(
            entry.get("DeviceName") == root and entry.get("Ebs", {}).get("VolumeId") for entry in mappings)
        if not root_present or not observed or not all(isinstance(value, str) and re.fullmatch(r"vol-[0-9a-f]{8,17}", value) for value in observed):
            # An earlier complete inventory is the only acceptable evidence if expiry
            # has already terminated an instance and its mappings disappeared.
            if mappings or instance.get("State", {}).get("Name") != "terminated" or previous is None:
                raise ValueError("Instance volume mappings are incomplete")
            observed = []
        captured[instance_id] = sorted(set(observed) | set((previous or {}).get(instance_id, [])))
    candidate = {**state, "volumeInventory": captured}
    if not valid_volume_inventory(candidate):
        raise ValueError("Volume inventory is incomplete or ambiguous")
    state["volumeInventory"] = captured


def recorded_volumes_absent(state):
    if not valid_volume_inventory(state):
        return False
    absent = True
    for volumes in state["volumeInventory"].values():
        for volume_id in volumes:
            try:
                # A successful query, even an unexpectedly empty one, does not prove
                # deletion. Require the specific AWS not-found response for each ID.
                aws("ec2", "describe-volumes", "--volume-ids", volume_id)
                absent = False
            except AwsCliError as error:
                if not error.volume_not_found:
                    raise
    return absent


RESERVED_ENV = {"BOWER_LAB_RUN", "BOWER_LAB_BUCKET", "BOWER_LAB_HOST", "AWS_DEFAULT_REGION"}


def parse_environment(items):
    result = {}
    seen = set()
    for item in items:
        key, separator, value = item.partition("=")
        canonical = key.upper()
        if (not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,40}", key)
                or not re.fullmatch(r"[A-Za-z0-9_.:/=+,@ -]{0,512}", value)
                or canonical in RESERVED_ENV or canonical in seen):
            raise ValueError("Invalid, duplicate or reserved public environment variable")
        seen.add(canonical)
        result[key] = value
    return result


def verified_bucket(state, stack):
    bucket = state["outputs"]["Bucket"]
    live_outputs = {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}
    if not bucket.startswith(state["runId"]) or live_outputs.get("Bucket") != bucket:
        raise ValueError("Bucket does not match this run's live stack output")
    tags = aws("s3api", "get-bucket-tagging", "--bucket", bucket).get("TagSet", [])
    if not owned(tags, state["runId"]):
        raise ValueError("Bucket does not belong to this run")
    return bucket


def send(state, host, script, env, timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 7200:
        raise ValueError("SSM execution timeout must be between 1 and 7200 seconds")
    env = parse_environment([f"{key}={value}" for key, value in env.items()])
    verify_account()
    stack = verify_stack(state)
    bucket = verified_bucket(state, stack)
    live_outputs = {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}
    if live_outputs.get(host + "Id") != state["outputs"][host + "Id"]:
        raise ValueError("Host does not match this run's live stack output")
    instance_id = verify_host(state, host)
    values = {"BOWER_LAB_RUN": state["runId"], "BOWER_LAB_BUCKET": bucket,
              "BOWER_LAB_HOST": host, "AWS_DEFAULT_REGION": REGION, **env}
    prefix = "\n".join("export " + k + "=" + shlex.quote(v) for k, v in values.items())
    body = script.read_text(encoding="utf-8")
    response = aws("ssm", "send-command", "--instance-ids", instance_id, "--document-name", "AWS-RunShellScript",
                   "--parameters", json.dumps({"commands": [prefix + "\n" + body], "executionTimeout": [str(timeout)]}),
                   "--timeout-seconds", "600", "--comment", (state["runId"] + " " + script.name)[:100])
    record = {"commandId": response["Command"]["CommandId"], "instanceId": instance_id, "host": host,
              "script": script.name, "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
              "env": env, "executionTimeoutSeconds": timeout, "sentAt": datetime.now(timezone.utc).isoformat()}
    with (Path(state["directory"]) / "commands.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    return record


def wait(record, poll=5):
    """Bound polling by the execution timeout plus SSM delivery and observation margins."""
    execution_timeout = record.get("executionTimeoutSeconds")
    if isinstance(execution_timeout, bool) or not isinstance(execution_timeout, int) or not 1 <= execution_timeout <= 7200:
        raise ValueError("Missing or invalid SSM execution timeout")
    if poll <= 0:
        raise ValueError("Polling interval must be positive")
    # send-command allows 600 seconds for delivery; reserve another minute for
    # propagation and status observation. Bound each CLI call as well as the loop.
    deadline = time.monotonic() + execution_timeout + 600 + 60
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SSM invocation did not finish within the polling deadline")
        try:
            result = aws("ssm", "get-command-invocation", "--command-id", record["commandId"],
                         "--instance-id", record["instanceId"], timeout=min(30, remaining))
        except AwsCliError as error:
            # The invocation can take a short time to appear after send-command.
            if not error.invocation_not_found:
                raise RuntimeError("SSM invocation lookup failed") from None
        except TimeoutError:
            pass
        else:
            status = result.get("Status")
            if status in ("Success", "Failed", "TimedOut", "Cancelled"):
                return result
            if status not in ("Pending", "InProgress", "Delayed", "Cancelling"):
                raise RuntimeError("SSM invocation returned an invalid status")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SSM invocation did not finish within the polling deadline")
        time.sleep(min(poll, remaining))


def audit(state):
    """Independent queries proving absence of everything this run created."""
    run = state["runId"]
    tag = ["Name=tag:RunId,Values=" + run]
    checks = {}
    stacks = aws("cloudformation", "list-stacks")["StackSummaries"]
    live = [s for s in stacks if s["StackName"] == state["stack"] and s["StackStatus"] != "DELETE_COMPLETE"]
    checks["stackDeleted"] = not live
    instances = [i for r in aws("ec2", "describe-instances", "--filters", *tag)["Reservations"] for i in r["Instances"]]
    ids = [state.get("outputs", {}).get(h + "Id") for h in HOSTS]
    complete_ids = all(isinstance(value, str) and re.fullmatch(r"i-[0-9a-f]{8,17}", value) for value in ids) and len(set(ids)) == len(HOSTS)
    checks["instancesTerminated"] = complete_ids and all(i["State"]["Name"] == "terminated" for i in instances)
    checks["allRunInstancesObserved"] = complete_ids and set(ids) <= {i["InstanceId"] for i in instances}
    checks["noVolumes"] = not aws("ec2", "describe-volumes", "--filters", *tag)["Volumes"]
    checks["noRecordedVolumes"] = recorded_volumes_absent(state)
    checks["noSnapshots"] = not aws("ec2", "describe-snapshots", "--owner-ids", "self", "--filters", *tag)["Snapshots"]
    checks["noSecurityGroups"] = not aws("ec2", "describe-security-groups", "--filters", *tag)["SecurityGroups"]
    checks["noSubnets"] = not aws("ec2", "describe-subnets", "--filters", *tag)["Subnets"]
    checks["noRouteTables"] = not aws("ec2", "describe-route-tables", "--filters", *tag)["RouteTables"]
    subnet = state.get("outputs", {}).get("SubnetId")
    checks["noSubnetInterfaces"] = isinstance(subnet, str) and bool(re.fullmatch(r"subnet-[0-9a-f]{8,17}", subnet)) and not aws("ec2", "describe-network-interfaces", "--filters",
                                                            "Name=subnet-id,Values=" + subnet)["NetworkInterfaces"]
    roles = [r["RoleName"] for r in aws("iam", "list-roles")["Roles"] if r["RoleName"].startswith(run)]
    checks["noIamRoles"] = not roles
    profiles = [p["InstanceProfileName"] for p in aws("iam", "list-instance-profiles")["InstanceProfiles"]
                if p["InstanceProfileName"].startswith(run)]
    checks["noInstanceProfiles"] = not profiles
    buckets = [b["Name"] for b in aws("s3api", "list-buckets")["Buckets"] if b["Name"].startswith(run)]
    checks["noBuckets"] = not buckets
    recorded = {r["type"]: r["physicalId"] for r in state.get("resources", [])}
    machine = recorded.get("AWS::StepFunctions::StateMachine")
    machines = [m["stateMachineArn"] for m in aws("stepfunctions", "list-state-machines")["stateMachines"]
                if m["stateMachineArn"] == machine]
    checks["noStateMachines"] = bool(machine) and not machines
    schedule = recorded.get("AWS::Scheduler::Schedule")
    schedules = [s["Name"] for s in aws("scheduler", "list-schedules")["Schedules"] if s["Name"] == schedule]
    checks["noSchedules"] = bool(schedule) and not schedules
    groups = aws("logs", "describe-log-groups", "--log-group-name-prefix", "/" + run).get("logGroups", [])
    checks["noLogGroups"] = not groups
    secrets = aws("secretsmanager", "list-secrets", "--filters", "Key=tag-value,Values=" + run)["SecretList"]
    checks["noSecrets"] = not secrets
    nat = aws("ec2", "describe-nat-gateways", "--nat-gateway-ids", state["parameters"]["NatGatewayId"])["NatGateways"][0]
    checks["sharedNatUntouched"] = nat["State"] == "available"
    return {"checkedAt": datetime.now(timezone.utc).isoformat(), "runId": run, "account": ACCOUNT, "region": REGION,
            "instances": {i["InstanceId"]: i["State"]["Name"] for i in instances}, "checks": checks,
            "remaining": {"roles": roles, "profiles": profiles, "buckets": buckets, "stateMachines": machines,
                          "schedules": schedules, "secrets": [s["Name"] for s in secrets]},
            "passed": all(checks.values())}


def destroy_run(state, state_path):
    """Delete only the bucket and stack verified as belonging to this run."""
    verify_account()
    stack = verify_stack(state)
    bucket = verified_bucket(state, stack)
    capture_volume_inventory(state, stack)
    save_state(state_path, state)
    aws_wait_or_remove("s3", "rm", "s3://" + bucket, "--recursive")
    versions = aws("s3api", "list-object-versions", "--bucket", bucket)
    for item in versions.get("Versions", []) + versions.get("DeleteMarkers", []):
        aws("s3api", "delete-object", "--bucket", bucket, "--key", item["Key"], "--version-id", item["VersionId"])
    aws("cloudformation", "delete-stack", "--stack-name", state["stack"])
    aws_wait_or_remove("cloudformation", "wait", "stack-delete-complete", "--stack-name", state["stack"])
    print("deleted " + state["stack"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("template", "plan", "apply", "status", "run", "destroy", "audit", "return-path"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--hours", type=int, default=10, choices=range(1, 13))
    parser.add_argument("--nat", help="Existing NAT gateway in the default VPC (never modified)")
    parser.add_argument("--cidr", default="172.31.201.0/24")
    parser.add_argument("--host", choices=tuple(HOSTS))
    parser.add_argument("--script", type=Path)
    parser.add_argument("--env", action="append", default=[], help="KEY=VALUE public value for the host script")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--wait", action="store_true")
    args = parser.parse_args()
    if args.action == "template":
        args.state.write_text(json.dumps(template(), indent=1) + "\n", encoding="utf-8")
        return
    verify_account()
    if args.action == "plan":
        if args.state.exists() or not args.run_id or not re.fullmatch(RUN_PATTERN, args.run_id) or not args.nat:
            raise ValueError("plan needs a new state path, --run-id and --nat")
        vpc = aws("ec2", "describe-vpcs", "--filters", "Name=is-default,Values=true")["Vpcs"][0]["VpcId"]
        nat = aws("ec2", "describe-nat-gateways", "--nat-gateway-ids", args.nat)["NatGateways"][0]
        if nat["VpcId"] != vpc or nat["State"] != "available":
            raise ValueError("NAT gateway must be available in the default VPC")
        zone = aws("ec2", "describe-subnets", "--subnet-ids", nat["SubnetId"])["Subnets"][0]["AvailabilityZone"]
        image = aws("ssm", "get-parameters", "--names",
                    "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameters"][0]["Value"]
        expiry = (datetime.now(timezone.utc) + timedelta(hours=args.hours)).strftime("%Y-%m-%dT%H:%M:%S")
        directory = args.state.parent
        directory.mkdir(parents=True, exist_ok=True)
        template_path = directory / "template.json"
        template_path.write_text(json.dumps(template(), indent=1) + "\n", encoding="utf-8")
        values = {"RunId": args.run_id, "Expiry": expiry, "VpcId": vpc, "NatGatewayId": args.nat,
                  "SubnetCidr": args.cidr, "AvailabilityZone": zone, "LinuxImage": image}
        state = {"runId": args.run_id, "stack": args.run_id, "expiry": expiry, "parameters": values,
                 "directory": str(directory.resolve())}
        run_tags = [{"Key": "Project", "Value": "bower-lab"}, {"Key": "RunId", "Value": args.run_id},
                    {"Key": "Owner", "Value": "Bower-test"}, {"Key": "Expiry", "Value": expiry}]
        response = aws("cloudformation", "create-change-set", "--stack-name", args.run_id, "--change-set-name", "reviewed",
                       "--change-set-type", "CREATE", "--capabilities", "CAPABILITY_IAM",
                       "--template-body", "file://" + str(template_path.resolve()),
                       "--parameters", json.dumps([{"ParameterKey": k, "ParameterValue": v} for k, v in values.items()]),
                       "--tags", json.dumps(run_tags))
        state["changeSet"] = response["Id"]
        save_state(args.state, state)
        print(json.dumps(state, indent=2))
        return
    state = load_state(args.state)
    if args.action == "audit":
        result = audit(state)
        print(json.dumps(result, indent=2))
        return
    stack = verify_stack(state)
    if args.action == "apply":
        changes = aws("cloudformation", "describe-change-set", "--change-set-name", state["changeSet"])
        if changes["ExecutionStatus"] != "AVAILABLE" or any(c["ResourceChange"]["Action"] != "Add" for c in changes["Changes"]):
            raise ValueError("Change set is not an unexecuted add-only plan")
        aws("cloudformation", "execute-change-set", "--change-set-name", state["changeSet"])
        print("started " + state["stack"])
    elif args.action == "status":
        state["stackStatus"] = stack["StackStatus"]
        state["outputs"] = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
        state["resources"] = [{"logicalId": r["LogicalResourceId"], "type": r["ResourceType"],
                               "physicalId": r.get("PhysicalResourceId", "")}
                              for r in aws("cloudformation", "describe-stack-resources",
                                           "--stack-name", state["stack"])["StackResources"]]
        if all(h + "Id" in state["outputs"] for h in HOSTS):
            capture_volume_inventory(state, stack)
        save_state(args.state, state)
        ids = [state["outputs"][h + "Id"] for h in HOSTS if h + "Id" in state["outputs"]]
        managed = aws("ssm", "describe-instance-information", "--filters",
                      json.dumps([{"Key": "InstanceIds", "Values": ids}])) if ids else {}
        print(json.dumps({"status": stack["StackStatus"], "outputs": state["outputs"],
                          "ssm": {i["InstanceId"]: i["PingStatus"] for i in managed.get("InstanceInformationList", [])}}, indent=2))
    elif args.action == "run":
        env = parse_environment(args.env)
        record = send(state, args.host, args.script, env, args.timeout)
        if args.wait:
            result = wait(record)
            print(result["StandardOutputContent"])
            if result["StandardErrorContent"].strip():
                print("--- stderr ---\n" + result["StandardErrorContent"])
            print(json.dumps({"status": result["Status"], "commandId": record["commandId"]}))
        else:
            print(json.dumps(record))
    elif args.action == "return-path":
        # Reviewed update of this run's own stack: toggles only the optional egress rule.
        enable = args.env == ["enable"]
        template_path = Path(state["directory"]) / "template.json"
        template_path.write_text(json.dumps(template(), indent=1) + "\n", encoding="utf-8")
        params = [{"ParameterKey": k, "UsePreviousValue": True} for k in state["parameters"]]
        params.append({"ParameterKey": "ReturnPath", "ParameterValue": "true" if enable else "false"})
        name = "return-path-" + ("on" if enable else "off") + "-" + datetime.now(timezone.utc).strftime("%H%M%S")
        created = aws("cloudformation", "create-change-set", "--stack-name", state["stack"], "--change-set-name", name,
                      "--change-set-type", "UPDATE", "--capabilities", "CAPABILITY_IAM",
                      "--template-body", "file://" + str(template_path.resolve()), "--parameters", json.dumps(params))
        aws_wait_or_remove("cloudformation", "wait", "change-set-create-complete", "--change-set-name", created["Id"])
        changes = aws("cloudformation", "describe-change-set", "--change-set-name", created["Id"])["Changes"]
        summary = [(c["ResourceChange"]["Action"], c["ResourceChange"]["LogicalResourceId"]) for c in changes]
        if summary != [("Add" if enable else "Remove", "CollectorReturnPath")]:
            raise ValueError("Unexpected change set: " + json.dumps(summary))
        aws("cloudformation", "execute-change-set", "--change-set-name", created["Id"])
        aws_wait_or_remove("cloudformation", "wait", "stack-update-complete", "--stack-name", state["stack"])
        print(json.dumps({"returnPath": enable, "changes": summary}))
    elif args.action == "destroy":
        destroy_run(state, args.state)

if __name__ == "__main__":
    main()
