#!/usr/bin/env python3
"""CloudFormation for the monitoring drill: one Linux syslog collector and one Windows WEC
collector in a new private subnet of an existing VPC, using an existing NAT gateway.

No public addresses, SSM administration only, encrypted disks, IMDSv2, and an
independent EventBridge Scheduler expiry. An optional separate Linux sender permits
only sender-to-Linux-collector TLS on port 6514 and is included in expiry when enabled.
"""

import argparse
import json
from pathlib import Path


def ref(name):
    return {"Ref": name}


def sub(text):
    return {"Fn::Sub": text}


def attr(name, attribute):
    return {"Fn::GetAtt": [name, attribute]}


def sender_enabled(yes, no=None):
    return {"Fn::If": ["WithSyslogSender", yes, ref("AWS::NoValue") if no is None else no]}


def context(why, *constraints):
    return {"com.aws.cloudformation.Context": {"why": why, "must": list(constraints)}}


def template():
    resources = {}

    def add(name, kind, properties, **extra):
        resources[name] = {"Type": "AWS::" + kind, "Properties": properties, **extra}
        return ref(name)

    def tags(role):
        return [{"Key": "Project", "Value": "bower-lab"}, {"Key": "RunId", "Value": ref("RunId")},
                {"Key": "Role", "Value": role}, {"Key": "Name", "Value": sub("${RunId}-" + role)}]

    subnet = add("PrivateSubnet", "EC2::Subnet", {"VpcId": ref("VpcId"), "CidrBlock": ref("SubnetCidr"),
        "AvailabilityZone": ref("AvailabilityZone"), "MapPublicIpOnLaunch": False, "Tags": tags("private")})
    routes = add("PrivateRoutes", "EC2::RouteTable", {"VpcId": ref("VpcId"), "Tags": tags("private")})
    add("PrivateAssociation", "EC2::SubnetRouteTableAssociation", {"SubnetId": subnet, "RouteTableId": routes})
    add("PrivateRoute", "EC2::Route", {"RouteTableId": routes, "DestinationCidrBlock": "0.0.0.0/0",
        "NatGatewayId": ref("NatGatewayId")})
    group = add("HostGroup", "EC2::SecurityGroup", {"GroupDescription": "Bower monitoring drill hosts: no inbound",
        "VpcId": ref("VpcId"), "SecurityGroupIngress": [],
        "SecurityGroupEgress": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0", "Description": "HTTPS"},
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": "0.0.0.0/0", "Description": "Package mirrors"}],
        "Tags": tags("hosts")})
    collector_group = add("CollectorSyslogGroup", "EC2::SecurityGroup", {
        "GroupDescription": "Optional sender can reach only the Linux collector TLS listener",
        "VpcId": ref("VpcId"), "SecurityGroupIngress": [],
        # An explicit egress rule suppresses EC2's implicit allow-all egress.
        "SecurityGroupEgress": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "CidrIp": "0.0.0.0/0", "Description": "HTTPS already allowed by HostGroup"}],
        "Tags": tags("collector-syslog")}, Condition="WithSyslogSender",
        Metadata=context("Attach the optional TLS ingress only to Linux, never Windows.",
            "Only SenderGroup may initiate TCP 6514; no public or administrative ingress."))
    sender_group = add("SenderGroup", "EC2::SecurityGroup", {
        "GroupDescription": "Optional nftables sender: TLS egress to this collector only",
        "VpcId": ref("VpcId"), "SecurityGroupIngress": [],
        "SecurityGroupEgress": [{"IpProtocol": "tcp", "FromPort": 6514, "ToPort": 6514,
            "DestinationSecurityGroupId": collector_group, "Description": "Synthetic firewall syslog TLS"}],
        "Tags": tags("syslog-sender")}, Condition="WithSyslogSender",
        Metadata=context("Separate firewall generation and buffering from collector faults.",
            "No inbound rules; HostGroup supplies existing HTTPS and package-mirror egress."))
    add("SenderToCollectorSyslog", "EC2::SecurityGroupIngress", {
        "GroupId": collector_group, "SourceSecurityGroupId": sender_group,
        "IpProtocol": "tcp", "FromPort": 6514, "ToPort": 6514,
        "Description": "Only the optional lab sender to Linux collector TLS"},
        Condition="WithSyslogSender",
        Metadata=context("Permit the synthetic firewall feed without exposing Windows or administration.",
            "Keep source and destination security groups scoped to this stack."))
    bucket = add("Artifacts", "S3::Bucket", {
        "BucketEncryption": {"ServerSideEncryptionConfiguration": [
            {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True,
            "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
        "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
        "LifecycleConfiguration": {"Rules": [{"Id": "expire", "Status": "Enabled", "ExpirationInDays": 2}]},
        "Tags": tags("artifacts")})
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role = add("HostRole", "IAM::Role", {"AssumeRolePolicyDocument": trust,
        "ManagedPolicyArns": [sub("arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore")],
        "Policies": [{"PolicyName": "DrillArtifacts", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": sub("${Artifacts.Arn}/artifacts/*")},
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": attr("Artifacts", "Arn"),
             "Condition": {"StringLike": {"s3:prefix": ["artifacts/*"]}}},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": sub("${Artifacts.Arn}/results/*")}]}}],
        "Tags": tags("hosts")})
    profile = add("HostProfile", "IAM::InstanceProfile", {"Roles": [role]})
    sender_role = add("SenderRole", "IAM::Role", {"AssumeRolePolicyDocument": trust,
        "ManagedPolicyArns": [sub("arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore")],
        "Policies": [{"PolicyName": "OnlySenderArtifacts", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject",
             "Resource": sub("${Artifacts.Arn}/artifacts/qualification/${RunId}/sender/*")},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": sub("${Artifacts.Arn}/results/sender/*")}]}}],
        "Tags": tags("syslog-sender")}, Condition="WithSyslogSender",
        Metadata=context("The separate sender must not read collector or Azure ingestion private keys.",
            "Allow only this run's sender artifact prefix and sender result prefix, plus SSM."))
    sender_profile = add("SenderProfile", "IAM::InstanceProfile", {"Roles": [sender_role]},
        Condition="WithSyslogSender",
        Metadata=context("Bind the optional sender to its restricted role.", "Do not reuse HostProfile for Sender."))
    hosts = {"Linux": ("linux-collector", "LinuxImage", "t3.small", "/dev/xvda", 20),
             "Windows": ("windows-wec", "WindowsImage", "t3.medium", "/dev/sda1", 40),
             "Sender": ("syslog-sender", "LinuxImage", "t3.small", "/dev/xvda", 20)}
    outputs = {"Bucket": {"Value": bucket}, "SubnetId": {"Value": subnet}, "SecurityGroupId": {"Value": group}}
    for name, (role_name, image, size, device, disk) in hosts.items():
        groups = [group]
        extra = {}
        if name == "Linux":
            groups.append(sender_enabled(collector_group))
            extra["Metadata"] = context("Linux collector for local and optional remote syslog qualification.",
                "Only conditional CollectorSyslogGroup may add inbound TLS.")
        elif name == "Sender":
            groups.append(sender_group)
            extra = {"Condition": "WithSyslogSender", "Metadata": context(
                "Disposable independent nftables and rsyslog source for collector fault tests.",
                "Private subnet, SSM only, run tags, encrypted disposable disks, and independent expiry.")}
        add(name, "EC2::Instance", {"ImageId": ref(image), "InstanceType": size, "SubnetId": subnet,
            "SecurityGroupIds": groups, "IamInstanceProfile": sender_profile if name == "Sender" else profile,
            "InstanceInitiatedShutdownBehavior": "terminate",
            "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1, "HttpEndpoint": "enabled"},
            "BlockDeviceMappings": [{"DeviceName": device, "Ebs": {"VolumeSize": disk, "VolumeType": "gp3",
                "Encrypted": True, "DeleteOnTermination": True}}],
            "PropagateTagsToVolumeOnCreation": True,
            "Tags": tags(role_name)}, DependsOn=["PrivateRoute", "PrivateAssociation"], **extra)
        outputs[name + "Id"] = {"Value": ref(name)}
        outputs[name + "Ip"] = {"Value": attr(name, "PrivateIp")}
        if name == "Sender":
            outputs[name + "Id"]["Condition"] = "WithSyslogSender"
            outputs[name + "Ip"]["Condition"] = "WithSyslogSender"
    # Independent expiry: terminates exactly these instances even if the operator disappears.
    instances = [sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${" + name + "}")
                 for name in ("Linux", "Windows")]
    instances.append(sender_enabled(sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${Sender}")))
    add("ExpiryRole", "IAM::Role", {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}}]},
        "Policies": [{"PolicyName": "TerminateOnlyThisDrill", "PolicyDocument": {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ec2:TerminateInstances", "Resource": instances}]}}],
        "Tags": tags("expiry")}, Metadata=context("Expiry may terminate only instances owned by this stack.",
            "Include Sender only with WithSyslogSender; never use a wildcard instance resource."))
    add("ExpirySchedule", "Scheduler::Schedule", {"ScheduleExpression": sub("at(${Expiry})"),
        "ScheduleExpressionTimezone": "UTC", "FlexibleTimeWindow": {"Mode": "OFF"},
        "Target": {"Arn": "arn:aws:scheduler:::aws-sdk:ec2:terminateInstances", "RoleArn": attr("ExpiryRole", "Arn"),
            "Input": sender_enabled(
                {"Fn::Sub": ['{"InstanceIds":["${L}","${W}","${S}"]}',
                    {"L": ref("Linux"), "W": ref("Windows"), "S": ref("Sender")}]},
                {"Fn::Sub": ['{"InstanceIds":["${L}","${W}"]}', {"L": ref("Linux"), "W": ref("Windows")}]})}},
        Metadata=context("Independent expiry bounds abandoned-run instance charges.",
            "Target exactly Linux and Windows, plus Sender only when enabled; teardown must still delete the stack."))
    return {"AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Bower monitoring drill: private Linux and Windows collectors, optional isolated firewall sender, SSM only, self-expiring",
        "Metadata": {"AWSToolsMetrics": {"AWSAgentToolkit": "aws-cloudformation@2"}},
        "Conditions": {"WithSyslogSender": {"Fn::Equals": [ref("EnableSyslogSender"), "true"]}},
        "Parameters": {
            "EnableSyslogSender": {"Type": "String", "Default": "false", "AllowedValues": ["true", "false"],
                "Description": "Create a separate Linux nftables/rsyslog sender; permit only its TLS feed to Linux."},
            "RunId": {"Type": "String", "AllowedPattern": "bower-ws6-[0-9]{8}-[0-9]{6}"},
            "Expiry": {"Type": "String", "AllowedPattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"},
            "VpcId": {"Type": "AWS::EC2::VPC::Id"},
            "NatGatewayId": {"Type": "String", "AllowedPattern": "nat-[0-9a-f]{8,17}"},
            "SubnetCidr": {"Type": "String", "AllowedPattern": "[0-9.]+/24"},
            "AvailabilityZone": {"Type": "AWS::EC2::AvailabilityZone::Name"},
            "LinuxImage": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"},
            "WindowsImage": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"},
        }, "Resources": resources, "Outputs": outputs}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(template(), indent=1) + "\n", encoding="utf-8")
