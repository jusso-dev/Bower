#!/usr/bin/env python3
"""Disposable storage-pressure lab: template, guarded apply, SSM runs and teardown.

Three private hosts in one new subnet of an existing VPC that already routes
through a NAT gateway: an Amazon Linux syslog collector with a 1 GiB queue volume,
and a Windows domain controller plus WEC/collector with a 2 GiB queue volume.
No public addresses, no inbound administration, SSM only, encrypted disks,
IMDSv2 and an independent expiry guard that terminates the hosts.
"""
import argparse
import datetime as dt
import hashlib
import json
import re
import shlex
import subprocess
import time
from pathlib import Path

HOSTS = {"Linux": "linux-collector", "Dc": "windows-dc", "Wec": "windows-wec"}
RUN_PATTERN = r"bower-ws3-\d{8}-\d{6}"
MAXIMUM_HOURS = 12


def ref(name):
    return {"Ref": name}


def attr(name, field):
    return {"Fn::GetAtt": [name, field]}


def sub(value):
    return {"Fn::Sub": value}


def template():
    resources = {}

    def add(name, kind, properties, **extra):
        resources[name] = {"Type": f"AWS::{kind}", "Properties": properties, **extra}
        return ref(name)

    def tags(role):
        return [{"Key": key, "Value": value} for key, value in {
            "Project": "bower-lab", "RunId": ref("RunId"), "Owner": "Bower-test",
            "Expiry": ref("Expiry"), "Role": role}.items()]

    subnet = add("Subnet", "EC2::Subnet", {"VpcId": ref("VpcId"), "CidrBlock": ref("SubnetCidr"),
        "AvailabilityZone": ref("AvailabilityZone"), "MapPublicIpOnLaunch": False, "Tags": tags("private")})
    routes = add("Routes", "EC2::RouteTable", {"VpcId": ref("VpcId"), "Tags": tags("private")})
    add("RoutesAssociation", "EC2::SubnetRouteTableAssociation", {"SubnetId": subnet, "RouteTableId": routes})
    add("EgressRoute", "EC2::Route", {"RouteTableId": routes, "DestinationCidrBlock": "0.0.0.0/0",
        "NatGatewayId": ref("NatGatewayId")})
    group = add("Hosts", "EC2::SecurityGroup", {"GroupDescription": "Storage-pressure lab: members only, HTTPS egress",
        "VpcId": ref("VpcId"), "SecurityGroupEgress": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"},
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": "0.0.0.0/0"}],
        "Tags": tags("hosts")})
    # Domain, Kerberos, LDAP, RPC and WinRM between members only; nothing from outside.
    add("MemberIngress", "EC2::SecurityGroupIngress", {"GroupId": group, "IpProtocol": "-1", "SourceSecurityGroupId": group})
    add("MemberEgress", "EC2::SecurityGroupEgress", {"GroupId": group, "IpProtocol": "-1", "DestinationSecurityGroupId": group})

    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role = add("HostRole", "IAM::Role", {"AssumeRolePolicyDocument": trust,
        "ManagedPolicyArns": [sub("arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore")],
        "Policies": [{"PolicyName": "RunArtifacts", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": sub("arn:${AWS::Partition}:s3:::${Bucket}/${RunId}/artifacts/*")},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": sub("arn:${AWS::Partition}:s3:::${Bucket}/${RunId}/results/*")},
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
             "Resource": sub("arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:bower-lab/${RunId}/*")}]}}],
        "Tags": tags("hosts")})
    add("HostProfile", "IAM::InstanceProfile", {"Roles": [role]})

    outputs = {"SubnetId": {"Value": subnet}, "GroupId": {"Value": group}}
    for name, purpose in HOSTS.items():
        windows = name != "Linux"
        disks = [{"DeviceName": "/dev/sda1" if windows else "/dev/xvda", "Ebs": {"VolumeSize": 50 if windows else 16,
            "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}}]
        if name in ("Linux", "Wec"):
            # The dedicated queue volume under test: deliberately small.
            disks.append({"DeviceName": "/dev/sdf", "Ebs": {"VolumeSize": 1 if name == "Linux" else 2,
                "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}})
        add(name, "EC2::Instance", {"ImageId": ref("WindowsImage" if windows else "LinuxImage"),
            "InstanceType": "t3.medium" if windows else "t3.small", "SubnetId": subnet,
            "SecurityGroupIds": [group], "IamInstanceProfile": ref("HostProfile"),
            "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1, "HttpEndpoint": "enabled"},
            "InstanceInitiatedShutdownBehavior": "terminate", "BlockDeviceMappings": disks,
            "CreditSpecification": {"CPUCredits": "standard"},
            "Tags": tags(purpose) + [{"Key": "Name", "Value": sub("${RunId}-" + name.lower())}]},
            DependsOn=["EgressRoute", "RoutesAssociation"])
        outputs[name + "Id"] = {"Value": ref(name)}
        outputs[name + "Ip"] = {"Value": attr(name, "PrivateIp")}

    # Independent cost guard: terminates exactly these hosts (and their volumes) at
    # expiry even if the operator disappears. Teardown still deletes the stack.
    add("ExpiryWorkerRole", "IAM::Role", {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole",
         "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}}]},
        "Policies": [{"PolicyName": "TerminateOnlyThisLab", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "ec2:TerminateInstances", "Resource": [
                sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${" + name + "}") for name in HOSTS]}]}}],
        "Tags": tags("expiry")})
    add("ExpiryWorker", "StepFunctions::StateMachine", {"RoleArn": attr("ExpiryWorkerRole", "Arn"),
        "Definition": {"StartAt": "Terminate", "States": {"Terminate": {"Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:ec2:terminateInstances",
            "Parameters": {"InstanceIds": [ref(name) for name in HOSTS]}, "End": True}}},
        "Tags": tags("expiry")})
    add("ExpiryRole", "IAM::Role", {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole",
         "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}}]},
        "Policies": [{"PolicyName": "ExpireOnlyThisLab", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "states:StartExecution", "Resource": ref("ExpiryWorker")}]}}],
        "Tags": tags("expiry")})
    add("ExpirySchedule", "Scheduler::Schedule", {"ScheduleExpression": sub("at(${Expiry})"),
        "ScheduleExpressionTimezone": "UTC", "FlexibleTimeWindow": {"Mode": "OFF"},
        "Target": {"Arn": ref("ExpiryWorker"), "RoleArn": attr("ExpiryRole", "Arn"), "Input": "{}"}})
    return {"AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Disposable private Bower storage-pressure lab; all access through SSM",
        "Parameters": {
            "RunId": {"Type": "String", "AllowedPattern": RUN_PATTERN},
            "Expiry": {"Type": "String", "AllowedPattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"},
            "VpcId": {"Type": "AWS::EC2::VPC::Id"}, "NatGatewayId": {"Type": "String", "AllowedPattern": "nat-[0-9a-f]+"},
            "SubnetCidr": {"Type": "String"}, "AvailabilityZone": {"Type": "AWS::EC2::AvailabilityZone::Name"},
            "Bucket": {"Type": "String"},
            "LinuxImage": {"Type": "AWS::EC2::Image::Id"}, "WindowsImage": {"Type": "AWS::EC2::Image::Id"}},
        "Resources": resources, "Outputs": outputs}


def aws(profile, region, *args, parse=True):
    result = subprocess.run(["aws", "--profile", profile, "--region", region, "--output", "json", *args],
                            check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if parse and result.stdout.strip() else result.stdout


def verify_account(state):
    identity = aws(state["profile"], state["region"], "sts", "get-caller-identity")
    if identity["Account"] != state["account"]:
        raise SystemExit("Refusing: unexpected AWS account")
    return identity


def verify_host(state, name):
    instance_id = state["outputs"][name + "Id"]
    instance = aws(state["profile"], state["region"], "ec2", "describe-instances",
                   "--instance-ids", instance_id)["Reservations"][0]["Instances"][0]
    tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
    if tags.get("Project") != "bower-lab" or tags.get("RunId") != state["runId"]:
        raise SystemExit("Refusing: instance is outside this run")
    if instance["State"]["Name"] != "running":
        raise SystemExit("Refusing: instance is not running")
    if instance.get("PublicIpAddress"):
        raise SystemExit("Refusing: instance has a public address")
    return instance


def run(state_path, name, script, wait, timeout, extra):
    state = json.loads(state_path.read_text(encoding="utf-8"))
    verify_account(state)
    instance = verify_host(state, name)
    windows = instance.get("Platform") == "windows"
    if script.suffix != (".ps1" if windows else ".sh"):
        raise SystemExit("Script does not match host platform")
    values = {"BOWER_LAB_RUN": state["runId"], "BOWER_LAB_BUCKET": state["bucket"], "BOWER_LAB_HOST": name,
              "AWS_DEFAULT_REGION": state["region"], **extra}
    for key, value in values.items():
        if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", key) or not re.fullmatch(r"[A-Za-z0-9_.:/@+=,-]{0,512}", value):
            raise SystemExit("Refusing: public parameter has unexpected characters")
    if windows:
        prefix = "\n".join(f"$env:{key}='{value}'" for key, value in values.items())
    else:
        prefix = "\n".join(f"export {key}={shlex.quote(value)}" for key, value in values.items())
    body = prefix + "\n" + script.read_text(encoding="utf-8")
    response = aws(state["profile"], state["region"], "ssm", "send-command", "--instance-ids", instance["InstanceId"],
        "--document-name", "AWS-RunPowerShellScript" if windows else "AWS-RunShellScript",
        "--parameters", json.dumps({"commands": [body], "executionTimeout": [str(timeout)]}),
        "--timeout-seconds", "600", "--comment", f"{state['runId']} {script.name}"[:100])
    record = {"commandId": response["Command"]["CommandId"], "host": name, "instanceId": instance["InstanceId"],
              "script": script.name, "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
              "sentAt": dt.datetime.now(dt.timezone.utc).isoformat(), "parameters": sorted(extra)}
    with (state_path.parent / "commands.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    if not wait:
        print(json.dumps(record))
        return
    while True:
        time.sleep(5)
        try:
            result = aws(state["profile"], state["region"], "ssm", "get-command-invocation",
                         "--command-id", record["commandId"], "--instance-id", instance["InstanceId"])
        except subprocess.CalledProcessError:
            continue
        if result["Status"] not in ("Pending", "InProgress", "Delayed"):
            print(result["StandardOutputContent"])
            if result["StandardErrorContent"]:
                print("--- stderr ---\n" + result["StandardErrorContent"][-4000:])
            print(json.dumps({"status": result["Status"], "commandId": record["commandId"]}))
            return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("template").add_argument("output", type=Path)
    runner = commands.add_parser("run")
    runner.add_argument("--state", type=Path, required=True)
    runner.add_argument("host", choices=sorted(HOSTS))
    runner.add_argument("script", type=Path)
    runner.add_argument("--wait", action="store_true")
    runner.add_argument("--timeout", type=int, default=3600)
    runner.add_argument("--set", action="append", default=[], help="NAME=VALUE public parameter")
    args = parser.parse_args()
    if args.command == "template":
        args.output.write_text(json.dumps(template(), indent=1) + "\n", encoding="utf-8")
        return
    if not 30 <= args.timeout <= 6 * 3600:
        raise SystemExit("SSM execution timeout must be bounded")
    extra = dict(item.split("=", 1) for item in args.set)
    run(args.state, args.host, args.script, args.wait, args.timeout, extra)


if __name__ == "__main__":
    main()
