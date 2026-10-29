"""Generate the disposable seven-node CloudFormation lab (no credentials)."""

import argparse
import json
from pathlib import Path


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
            "Expiry": ref("Expiry"), "Role": role,
        }.items()]

    vpc = add("Vpc", "EC2::VPC", {"CidrBlock": "10.83.0.0/16", "EnableDnsSupport": True,
                                  "EnableDnsHostnames": True, "Tags": tags("network")})
    public = add("EgressSubnet", "EC2::Subnet", {"VpcId": vpc, "CidrBlock": "10.83.0.0/24",
        "AvailabilityZone": ref("AvailabilityZone"), "MapPublicIpOnLaunch": False, "Tags": tags("egress")})
    private = add("PrivateSubnet", "EC2::Subnet", {"VpcId": vpc, "CidrBlock": "10.83.1.0/24",
        "AvailabilityZone": ref("AvailabilityZone"), "MapPublicIpOnLaunch": False, "Tags": tags("private")})
    internet = add("InternetGateway", "EC2::InternetGateway", {"Tags": tags("egress")})
    add("GatewayAttachment", "EC2::VPCGatewayAttachment", {"VpcId": vpc, "InternetGatewayId": internet})
    public_routes = add("EgressRoutes", "EC2::RouteTable", {"VpcId": vpc, "Tags": tags("egress")})
    add("EgressAssociation", "EC2::SubnetRouteTableAssociation", {"SubnetId": public, "RouteTableId": public_routes})
    add("InternetRoute", "EC2::Route", {"RouteTableId": public_routes, "DestinationCidrBlock": "0.0.0.0/0",
        "GatewayId": internet}, DependsOn="GatewayAttachment")
    address = add("NatAddress", "EC2::EIP", {"Domain": "vpc", "Tags": tags("egress")}, DependsOn="GatewayAttachment")
    nat = add("Nat", "EC2::NatGateway", {"SubnetId": public, "AllocationId": attr("NatAddress", "AllocationId"), "Tags": tags("egress")})
    routes = add("PrivateRoutes", "EC2::RouteTable", {"VpcId": vpc, "Tags": tags("private")})
    add("PrivateAssociation", "EC2::SubnetRouteTableAssociation", {"SubnetId": private, "RouteTableId": routes})
    add("PrivateRoute", "EC2::Route", {"RouteTableId": routes, "DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": nat})
    bucket = add("Results", "S3::Bucket", {
        "BucketEncryption": {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        "PublicAccessBlockConfiguration": {key: True for key in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")},
        "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
        "LifecycleConfiguration": {"Rules": [{"Id": "expire-lab-data", "Status": "Enabled", "ExpirationInDays": 90,
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]}, "Tags": tags("reports"),
    }, DeletionPolicy="Retain", UpdateReplacePolicy="Retain")
    add("ResultsPolicy", "S3::BucketPolicy", {"Bucket": bucket, "PolicyDocument": {
        "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": [attr("Results", "Arn"), sub("${Results.Arn}/*")],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}})
    egress = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"}]
    nodes = add("NodeGroup", "EC2::SecurityGroup", {"GroupDescription": "Lab nodes: HTTPS egress and scoped internal traffic", "VpcId": vpc,
        "SecurityGroupEgress": egress, "Tags": tags("nodes")})
    control = add("ControlGroup", "EC2::SecurityGroup", {"GroupDescription": "SSM-only control; no public administration", "VpcId": vpc,
        "SecurityGroupEgress": egress, "Tags": tags("control")})
    endpoints = add("EndpointGroup", "EC2::SecurityGroup", {"GroupDescription": "Private endpoints from lab hosts only", "VpcId": vpc,
        "SecurityGroupIngress": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "SourceSecurityGroupId": group} for group in (nodes, control)],
        "SecurityGroupEgress": egress, "Tags": tags("endpoints")})
    for port in (443, 4319, 5986, 6514):
        add(f"NodeIngress{port}", "EC2::SecurityGroupIngress", {"GroupId": nodes, "IpProtocol": "tcp", "FromPort": port,
            "ToPort": port, "SourceSecurityGroupId": nodes})
        add(f"NodeEgress{port}", "EC2::SecurityGroupEgress", {"GroupId": nodes, "IpProtocol": "tcp", "FromPort": port,
            "ToPort": port, "DestinationSecurityGroupId": nodes})
    for port in (443, 4319):
        add(f"ControlToNode{port}", "EC2::SecurityGroupIngress", {"GroupId": nodes, "IpProtocol": "tcp", "FromPort": port,
            "ToPort": port, "SourceSecurityGroupId": control})
        add(f"ControlEgress{port}", "EC2::SecurityGroupEgress", {"GroupId": control, "IpProtocol": "tcp", "FromPort": port,
            "ToPort": port, "DestinationSecurityGroupId": nodes})
    add("ManagementIngress", "EC2::SecurityGroupIngress", {"GroupId": control, "IpProtocol": "tcp", "FromPort": 443,
        "ToPort": 443, "SourceSecurityGroupId": nodes})
    for name in ("ssm", "ssmmessages", "ec2messages", "logs", "secretsmanager"):
        add("Endpoint" + name, "EC2::VPCEndpoint", {"VpcId": vpc, "VpcEndpointType": "Interface",
            "ServiceName": sub("com.amazonaws.${AWS::Region}." + name), "PrivateDnsEnabled": True,
            "SubnetIds": [private], "SecurityGroupIds": [endpoints]})
    add("EndpointS3", "EC2::VPCEndpoint", {"VpcId": vpc, "VpcEndpointType": "Gateway",
        "ServiceName": sub("com.amazonaws.${AWS::Region}.s3"), "RouteTableIds": [routes]})

    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    s3_policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": sub("${Results.Arn}/artifacts/*")},
        {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": sub("${Results.Arn}/runs/${RunId}/*")},
        {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": sub("arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:bower-lab/${RunId}/*")},
    ]}
    for name in ("Node", "Control"):
        policies = [{"PolicyName": "LabArtifacts", "PolicyDocument": s3_policy}]
        if name == "Control":
            policies.append({"PolicyName": "RunLab", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["ec2:DescribeInstances", "ssm:DescribeInstanceInformation", "ssm:GetCommandInvocation", "ssm:ListCommandInvocations"], "Resource": "*"},
                {"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/*"),
                    "Condition": {"StringEquals": {"ssm:resourceTag/Project": "bower-lab", "ssm:resourceTag/RunId": ref("RunId")}}},
                {"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": [sub("arn:${AWS::Partition}:ssm:${AWS::Region}::document/AWS-RunShellScript"), sub("arn:${AWS::Partition}:ssm:${AWS::Region}::document/AWS-RunPowerShellScript")]},
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": sub("${Results.Arn}/runs/${RunId}/*")},
                {"Effect": "Allow", "Action": ["secretsmanager:CreateSecret", "secretsmanager:PutSecretValue", "secretsmanager:TagResource"],
                    "Resource": sub("arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:bower-lab/${RunId}/*")},
            ]}})
        role = add(name + "Role", "IAM::Role", {"AssumeRolePolicyDocument": trust,
            "ManagedPolicyArns": [sub("arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore")],
            "Policies": policies, "Tags": tags(name.lower())})
        add(name + "Profile", "IAM::InstanceProfile", {"Roles": [role]})

    hosts = {"Control": "control", "Collector": "collector", "Linux1": "linux-source", "Linux2": "linux-source",
             "Wec": "wec", "Windows1": "windows-source", "Windows2": "windows-source"}
    outputs = {"Bucket": {"Value": bucket}, "VpcId": {"Value": vpc}}
    for name, role in hosts.items():
        windows = name in ("Wec", "Windows1", "Windows2")
        disks = [{"DeviceName": "/dev/sda1" if windows else "/dev/xvda", "Ebs": {"VolumeSize": 40 if windows else 12,
            "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}}]
        if name == "Collector":
            disks.append({"DeviceName": "/dev/sdf", "Ebs": {"VolumeSize": 4, "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}})
        add(name, "EC2::Instance", {"ImageId": ref("WindowsImage" if windows else "LinuxImage"),
            "InstanceType": ref("WindowsType") if windows else "t3.micro", "SubnetId": private,
            "SecurityGroupIds": [control if name == "Control" else nodes],
            "IamInstanceProfile": ref("ControlProfile" if name == "Control" else "NodeProfile"),
            "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1},
            "CreditSpecification": {"CPUCredits": "unlimited"}, "BlockDeviceMappings": disks,
            "Tags": tags(role) + [{"Key": "Name", "Value": sub("bower-lab-${RunId}-" + name.lower())}],
        }, DependsOn=["PrivateRoute", "Endpointssm", "Endpointssmmessages"])
        outputs[name + "Id"] = {"Value": ref(name)}
        outputs[name + "Ip"] = {"Value": attr(name, "PrivateIp")}
    # Independent cost guard: terminate only these hosts and remove the chargeable
    # NAT/endpoints/address even if the client disappears. Normal teardown deletes
    # the whole stack; the guard deliberately leaves only free network/IAM objects.
    endpoint_names = ["Endpoint" + name for name in ("ssm", "ssmmessages", "ec2messages", "logs", "secretsmanager")]
    expiry_resources = [sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${" + name + "}") for name in hosts]
    expiry_resources += [sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:vpc-endpoint/${" + name + "}") for name in endpoint_names]
    expiry_resources += [sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:natgateway/${Nat}"),
                         sub("arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:elastic-ip/${NatAddress.AllocationId}")]
    add("ExpiryWorkerRole", "IAM::Role", {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole",
         "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}}]},
        "Policies": [{"PolicyName": "StopOnlyThisLab", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["ec2:TerminateInstances", "ec2:DeleteNatGateway", "ec2:DeleteVpcEndpoints", "ec2:ReleaseAddress"],
             "Resource": expiry_resources}]}}], "Tags": tags("expiry")})
    add("ExpiryWorker", "StepFunctions::StateMachine", {"RoleArn": attr("ExpiryWorkerRole", "Arn"),
        "Definition": {"StartAt": "Terminate", "States": {
            "Terminate": {"Type": "Task", "Resource": "arn:aws:states:::aws-sdk:ec2:terminateInstances",
                "Parameters": {"InstanceIds": [ref(name) for name in hosts]}, "ResultPath": "$.terminated", "Next": "Endpoints"},
            "Endpoints": {"Type": "Task", "Resource": "arn:aws:states:::aws-sdk:ec2:deleteVpcEndpoints",
                "Parameters": {"VpcEndpointIds": [ref(name) for name in endpoint_names]}, "ResultPath": "$.endpoints", "Next": "Nat"},
            "Nat": {"Type": "Task", "Resource": "arn:aws:states:::aws-sdk:ec2:deleteNatGateway",
                "Parameters": {"NatGatewayId": ref("Nat")}, "ResultPath": "$.nat", "Next": "WaitForNat"},
            "WaitForNat": {"Type": "Wait", "Seconds": 120, "Next": "Address"},
            "Address": {"Type": "Task", "Resource": "arn:aws:states:::aws-sdk:ec2:releaseAddress",
                "Parameters": {"AllocationId": attr("NatAddress", "AllocationId")},
                "Retry": [{"ErrorEquals": ["States.TaskFailed"], "IntervalSeconds": 60, "MaxAttempts": 15, "BackoffRate": 1.0}], "End": True},
        }}, "Tags": tags("expiry")})
    add("ExpiryRole", "IAM::Role", {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole",
         "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}}]},
        "Policies": [{"PolicyName": "ExpireOnlyThisLab", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "states:StartExecution", "Resource": ref("ExpiryWorker")}]}}], "Tags": tags("expiry")})
    add("ExpirySchedule", "Scheduler::Schedule", {"ScheduleExpression": sub("at(${Expiry})"), "ScheduleExpressionTimezone": "UTC",
        "FlexibleTimeWindow": {"Mode": "OFF"},
        "Target": {"Arn": ref("ExpiryWorker"), "RoleArn": attr("ExpiryRole", "Arn"), "Input": "{}"}})
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": "Disposable private Bower Linux/Windows lab; all access through SSM",
        "Parameters": {
            "RunId": {"Type": "String", "AllowedPattern": "[a-z0-9-]{1,40}"},
            "Expiry": {"Type": "String", "AllowedPattern": "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"},
            "AvailabilityZone": {"Type": "AWS::EC2::AvailabilityZone::Name"},
            "LinuxImage": {"Type": "AWS::EC2::Image::Id"}, "WindowsImage": {"Type": "AWS::EC2::Image::Id"},
            "WindowsType": {"Type": "String", "Default": "t3.micro", "AllowedValues": ["t3.micro", "t3.small"]},
        }, "Resources": resources, "Outputs": outputs}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(template(), indent=1) + "\n", encoding="utf-8")
