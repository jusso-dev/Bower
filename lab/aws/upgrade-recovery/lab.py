"""ws4 upgrade/recovery lab. Owns only resources tagged Project=bower-lab, RunId=RUN.

Prints identifiers and metadata only; never credentials or payloads.
"""
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(os.environ['BOWER_LAB_DIR'])  # private working directory, never the checkout
STATE = ROOT / 'state.json'
ACCOUNT = '959038055523'
REGION = 'ap-southeast-2'
PROJECT = 'bower-lab'
RUN = os.environ['BOWER_LAB_RUN_ID']  # bower-<profile>-UTCyyyymmdd-HHMMSS
VPC = 'vpc-0386855f644985706'
NAT = 'nat-016cf975ae7ffe691'
# ws4 (default): upgrade/recovery. soak: the 24-hour soak (gap 7): Dc, Wec, the RPM collector
# Linux and the rsyslog/RELP Sender, which gets its own role limited to its artifact prefix.
# resoak: the same four hosts for the 72-hour re-soak (lab/aws/resoak) on fixed-performance
# instances, an 80-hour expiry and write access to the run's separate identity bucket.
PROFILE = os.environ.get('BOWER_LAB_PROFILE', 'ws4')
if PROFILE not in ('ws4', 'soak', 'resoak') or not __import__('re').fullmatch(r'bower-' + PROFILE + r'-\d{8}-\d{6}', RUN):
    raise SystemExit('BOWER_LAB_RUN_ID does not match BOWER_LAB_PROFILE')
# The Windows generators only target a DC inside their profile's subnet (generator.ps1:
# 172.31.244., soak/generator-windows.ps1: 172.31.247. or 172.31.248.); refuse any other subnet.
GENERATOR_SUBNET = {'ws4': '172.31.244.0/24', 'soak': '172.31.247.0/24', 'resoak': '172.31.248.0/24'}[PROFILE]
CIDR = os.environ.get('BOWER_LAB_CIDR', GENERATOR_SUBNET)
if CIDR != GENERATOR_SUBNET:
    raise SystemExit('BOWER_LAB_CIDR must be ' + GENERATOR_SUBNET + ' for profile ' + PROFILE
                     + ': the DC generator guard accepts only that subnet')
WINDOWS = ['Dc', 'Wec', 'Wec2'] if PROFILE == 'ws4' else ['Dc', 'Wec']
LINUX = ['Linux', 'Linux2'] if PROFILE == 'ws4' else ['Linux', 'Sender']
HOSTS = WINDOWS + LINUX
EXPIRY_HOURS = {'ws4': 10, 'soak': 30, 'resoak': 80}[PROFILE]
# A shorter guard (never a longer one), e.g. 12 hours for the re-soak's dry run.
if os.environ.get('BOWER_LAB_EXPIRY_HOURS'):
    EXPIRY_HOURS = min(EXPIRY_HOURS, int(os.environ['BOWER_LAB_EXPIRY_HOURS']))
# Results must outlive the run: the soak's one-day lifecycle would expire hourly uploads of a
# 72-hour run before the final reconciliation.
RESULTS_DAYS = 7 if PROFILE == 'resoak' else 1
# The identity lists of the re-soak go to a RunId-owned bucket outside the stack (created first by
# resoak/evidence_bucket.py), so they survive teardown of the stack until reconciliation is done.
EVIDENCE_BUCKET = RUN + '-ids' if PROFILE == 'resoak' else None


def aws(*args, raw=False):
    p = subprocess.run(['aws', '--profile', 'homelab-admin', '--region', REGION, *args, '--output', 'json'],
                       capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(p.stderr.strip()[:2000])
    return p.stdout if raw else (json.loads(p.stdout) if p.stdout.strip() else {})


def verify_account():
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('Wrong AWS account; nothing attempted')


def save(state):
    STATE.write_text(json.dumps(state, indent=2) + '\n')


def build(expiry):
    ref = lambda n: {'Ref': n}
    att = lambda n, k: {'Fn::GetAtt': [n, k]}
    sub = lambda t: {'Fn::Sub': t}
    res = lambda kind, **p: {'Type': kind, 'Properties': p}
    tags = [{'Key': 'Project', 'Value': PROJECT}, {'Key': 'RunId', 'Value': RUN}]
    win_ami = aws('ssm', 'get-parameter', '--name', '/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base')['Parameter']['Value']
    lin_ami = aws('ssm', 'get-parameter', '--name', '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64')['Parameter']['Value']
    nat = aws('ec2', 'describe-nat-gateways', '--nat-gateway-ids', NAT)['NatGateways'][0]
    if nat['State'] != 'available' or nat['VpcId'] != VPC:
        raise RuntimeError('Shared NAT unavailable')
    subnets = aws('ec2', 'describe-subnets', '--filters', 'Name=vpc-id,Values=' + VPC)['Subnets']
    zone = next(s['AvailabilityZone'] for s in subnets if s['SubnetId'] == nat['SubnetId'])
    if any(ipaddress.ip_network(CIDR).overlaps(ipaddress.ip_network(s['CidrBlock'])) for s in subnets):
        raise RuntimeError('Planned subnet overlaps an existing subnet')
    r = {
        'Subnet': res('AWS::EC2::Subnet', VpcId=VPC, CidrBlock=CIDR, AvailabilityZone=zone, MapPublicIpOnLaunch=False, Tags=tags),
        'Routes': res('AWS::EC2::RouteTable', VpcId=VPC, Tags=tags),
        'DefaultRoute': res('AWS::EC2::Route', RouteTableId=ref('Routes'), DestinationCidrBlock='0.0.0.0/0', NatGatewayId=NAT),
        'RouteAssociation': res('AWS::EC2::SubnetRouteTableAssociation', SubnetId=ref('Subnet'), RouteTableId=ref('Routes')),
        'Group': res('AWS::EC2::SecurityGroup', GroupDescription='Temporary Bower ws4 lab; SSM administration only', VpcId=VPC,
                     SecurityGroupIngress=[], SecurityGroupEgress=[{'IpProtocol': '-1', 'CidrIp': '0.0.0.0/0'}], Tags=tags),
        'Internal': res('AWS::EC2::SecurityGroupIngress', GroupId=ref('Group'), SourceSecurityGroupId=ref('Group'), IpProtocol='-1'),
        'Secret': res('AWS::SecretsManager::Secret', GenerateSecretString={'PasswordLength': 32, 'ExcludePunctuation': True}, Tags=tags),
        'Artifacts': res('AWS::S3::Bucket', BucketEncryption={'ServerSideEncryptionConfiguration': [{'ServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]},
                         PublicAccessBlockConfiguration={'BlockPublicAcls': True, 'BlockPublicPolicy': True, 'IgnorePublicAcls': True, 'RestrictPublicBuckets': True},
                         LifecycleConfiguration={'Rules': [{'Id': 'Expire', 'Status': 'Enabled', 'ExpirationInDays': RESULTS_DAYS}]}, Tags=tags),
    }
    r['BucketPolicy'] = res('AWS::S3::BucketPolicy', Bucket=ref('Artifacts'), PolicyDocument={'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Deny', 'Principal': '*', 'Action': 's3:*', 'Resource': [att('Artifacts', 'Arn'), sub('${Artifacts.Arn}/*')],
         'Condition': {'Bool': {'aws:SecureTransport': 'false'}}}]})
    statements = [
        {'Effect': 'Allow', 'Action': ['s3:GetObject'], 'Resource': [sub('${Artifacts.Arn}/artifacts/*'), sub('${Artifacts.Arn}/credentials/*')]},
        {'Effect': 'Allow', 'Action': ['s3:GetObject', 's3:PutObject'], 'Resource': [sub('${Artifacts.Arn}/backups/*'), sub('${Artifacts.Arn}/results/*')]},
        {'Effect': 'Allow', 'Action': ['secretsmanager:GetSecretValue'], 'Resource': ref('Secret')},
    ]
    if EVIDENCE_BUCKET:
        statements.append({'Effect': 'Allow', 'Action': ['s3:PutObject'],
                           'Resource': 'arn:aws:s3:::' + EVIDENCE_BUCKET + '/hosts/*'})
    r['HostRole'] = res('AWS::IAM::Role', AssumeRolePolicyDocument={'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]},
        ManagedPolicyArns=['arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'],
        Policies=[{'PolicyName': 'LabArtifacts', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': statements}}], Tags=tags)
    r['HostProfile'] = res('AWS::IAM::InstanceProfile', Roles=[ref('HostRole')])
    if 'Sender' in HOSTS:
        # The sender must not read collector or Azure ingestion private keys.
        r['SenderRole'] = res('AWS::IAM::Role', AssumeRolePolicyDocument={'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]},
            ManagedPolicyArns=['arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'],
            Policies=[{'PolicyName': 'OnlySenderArtifacts', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': sub('${Artifacts.Arn}/artifacts/qualification/' + RUN + '/sender/*')},
                {'Effect': 'Allow', 'Action': 's3:PutObject', 'Resource': sub('${Artifacts.Arn}/results/sender/*')}]
                + ([{'Effect': 'Allow', 'Action': 's3:PutObject', 'Resource': 'arn:aws:s3:::' + EVIDENCE_BUCKET + '/sender/*'}]
                   if EVIDENCE_BUCKET else [])}}], Tags=tags)
        r['SenderProfile'] = res('AWS::IAM::InstanceProfile', Roles=[ref('SenderRole')])
    sizes = {'Dc': 't3.medium', 'Wec': 't3.medium', 'Wec2': 't3.medium', 'Linux': 't3.medium', 'Linux2': 't3.small',
             'Sender': 't3.small'}
    if PROFILE == 'soak':
        sizes['Linux'] = 't3.small'
    if PROFILE == 'resoak':
        # Fixed performance: the first soak measured the t3 CPU-credit policy, not Bower.
        sizes = {name: 'm6i.large' for name in HOSTS}
    for name in HOSTS:
        win = name in WINDOWS
        r[name] = res('AWS::EC2::Instance', ImageId=win_ami if win else lin_ami, InstanceType=sizes[name],
                      IamInstanceProfile=ref('SenderProfile' if name == 'Sender' else 'HostProfile'),
                      MetadataOptions={'HttpTokens': 'required', 'HttpPutResponseHopLimit': 1},
                      **({} if PROFILE == 'resoak' else {'CreditSpecification': {'CPUCredits': 'standard'}}),
                      InstanceInitiatedShutdownBehavior='stop',
                      BlockDeviceMappings=[{'DeviceName': '/dev/sda1' if win else '/dev/xvda', 'Ebs': {
                          'VolumeType': 'gp3', 'VolumeSize': 40 if win else 30, 'Encrypted': True, 'DeleteOnTermination': True}}],
                      PropagateTagsToVolumeOnCreation=True,
                      NetworkInterfaces=[{'DeviceIndex': '0', 'SubnetId': ref('Subnet'), 'GroupSet': [ref('Group')],
                                          'AssociatePublicIpAddress': False, 'DeleteOnTermination': True}],
                      Tags=tags + [{'Key': 'Name', 'Value': RUN + '-' + name.lower()}])
        r[name]['DependsOn'] = ['DefaultRoute', 'RouteAssociation']
    r['ExpiryRole'] = res('AWS::IAM::Role', AssumeRolePolicyDocument={'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'Service': 'scheduler.amazonaws.com'}, 'Action': 'sts:AssumeRole',
         'Condition': {'StringEquals': {'aws:SourceAccount': ACCOUNT},
                       'ArnLike': {'aws:SourceArn': f'arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule-group/default'}}}]},
        Policies=[{'PolicyName': 'TerminateLab', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 'ec2:TerminateInstances',
             'Resource': [sub('arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:instance/${' + n + '}') for n in HOSTS]}]}}], Tags=tags)
    r['Expiry'] = res('AWS::Scheduler::Schedule', Name=RUN + '-expiry', ScheduleExpression='at(' + expiry + ')',
                      ScheduleExpressionTimezone='UTC', FlexibleTimeWindow={'Mode': 'OFF'},
                      Target={'Arn': 'arn:aws:scheduler:::aws-sdk:ec2:terminateInstances', 'RoleArn': att('ExpiryRole', 'Arn'),
                              'Input': sub('{"InstanceIds":[' + ','.join('"${' + n + '}"' for n in HOSTS) + ']}')})
    extra_outputs = ['SenderRole', 'SenderProfile'] if 'Sender' in HOSTS else []
    outputs = {n: {'Value': ref(n)} for n in HOSTS + ['Artifacts', 'Secret', 'Group', 'Subnet', 'Routes', 'HostRole', 'HostProfile', 'ExpiryRole', 'Expiry'] + extra_outputs}
    outputs.update({n + 'Ip': {'Value': att(n, 'PrivateIp')} for n in HOSTS})
    return {'AWSTemplateFormatVersion': '2010-09-09', 'Description': 'Bower ' + PROFILE + ' lab ' + RUN,
            'Resources': r, 'Outputs': outputs}


def check_instance(state, host, states=('running',)):
    instance = state['outputs'][host]
    info = aws('ec2', 'describe-instances', '--instance-ids', instance)['Reservations'][0]['Instances'][0]
    tags = {t['Key']: t['Value'] for t in info.get('Tags', [])}
    if tags.get('Project') != PROJECT or tags.get('RunId') != RUN or info['InstanceId'] != instance:
        raise RuntimeError('Instance ownership mismatch for ' + host)
    if info['State']['Name'] not in states:
        raise RuntimeError(f"{host} is {info['State']['Name']}")
    return instance


def render(state, host, script, extra):
    body = Path(script).read_text()
    values = {'REGION': REGION, 'HOST': host, 'RUN_ID': RUN, 'EVIDENCE_BUCKET': EVIDENCE_BUCKET or 'none', **state['outputs'], **extra}
    for key, value in values.items():
        body = body.replace('{{' + key + '}}', str(value))
    if any(not m.startswith(('{{.', '{{range', '{{end')) for m in __import__('re').findall(r'\{\{[^}]*\}\}', body)):
        raise RuntimeError('Unresolved placeholder in ' + str(script))
    return body


def main():
    verify_account()
    action = sys.argv[1]
    if action == 'plan':
        if STATE.exists() and json.loads(STATE.read_text()).get('stackId'):
            raise RuntimeError('Stack already created')
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=EXPIRY_HOURS)).strftime('%Y-%m-%dT%H:%M:%S')
        path = ROOT / 'template.json'
        path.write_text(json.dumps(build(expiry), indent=2) + '\n')
        aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(path))
        save({'run': RUN, 'account': ACCOUNT, 'region': REGION, 'expiry': expiry,
              'templateSha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        print(json.dumps({'run': RUN, 'expiry': expiry, 'template': str(path)}))
        return
    state = json.loads(STATE.read_text())
    if state['run'] != RUN or state['account'] != ACCOUNT:
        raise RuntimeError('Saved state mismatch')
    if action == 'create':
        path = ROOT / 'template.json'
        if hashlib.sha256(path.read_bytes()).hexdigest() != state['templateSha256']:
            raise RuntimeError('Template changed after review')
        created = aws('cloudformation', 'create-stack', '--stack-name', RUN, '--template-body', 'file://' + str(path),
                      '--capabilities', 'CAPABILITY_IAM', '--on-failure', 'DELETE',
                      '--tags', 'Key=Project,Value=' + PROJECT, 'Key=RunId,Value=' + RUN)
        state['stackId'] = created['StackId']
        save(state)
        print(json.dumps(created))
    elif action == 'status':
        stack = aws('cloudformation', 'describe-stacks', '--stack-name', RUN)['Stacks'][0]
        state['status'] = stack['StackStatus']
        state['outputs'] = {o['OutputKey']: o['OutputValue'] for o in stack.get('Outputs', [])}
        save(state)
        info = {}
        if state['outputs']:
            ssm = aws('ssm', 'describe-instance-information')['InstanceInformationList']
            online = {i['InstanceId']: i['PingStatus'] for i in ssm}
            info = {h: online.get(state['outputs'][h], 'missing') for h in HOSTS}
        print(json.dumps({'status': state['status'], 'ssm': info}))
    elif action == 'run':
        # run HOST SCRIPT [KEY=VALUE ...] ; values are non-secret placeholders only.
        # env:NAME=VALUE items instead export public variables for the monitoring/ scripts,
        # which read BOWER_LAB_BUCKET/BOWER_LAB_RUN from the environment, not placeholders.
        host, script = sys.argv[2:4]
        items = sys.argv[4:]
        env = dict(item[4:].split('=', 1) for item in items if item.startswith('env:'))
        extra = dict(item.split('=', 1) for item in items if not item.startswith('env:'))
        instance = check_instance(state, host)
        if env:
            if extra or any(not __import__('re').fullmatch(r'[A-Z][A-Z0-9_]*', k) for k in env):
                raise RuntimeError('Mixing placeholders and env:, or an invalid name')
            env = {'BOWER_LAB_BUCKET': state['outputs']['Artifacts'], 'BOWER_LAB_RUN': RUN, 'AWS_DEFAULT_REGION': REGION,
                   **({'BOWER_EVIDENCE_BUCKET': EVIDENCE_BUCKET} if EVIDENCE_BUCKET else {}), **env}
            if host in LINUX:
                prefix = '\n'.join('export ' + k + '=' + __import__('shlex').quote(v) for k, v in env.items())
            else:
                prefix = '\n'.join('$env:' + k + "='" + v.replace("'", "''") + "'" for k, v in env.items())
            body = prefix + '\n' + Path(script).read_text()
            extra = env
        else:
            body = render(state, host, script, extra)
        params = ROOT / 'parameters' / (host + '.json')
        params.parent.mkdir(exist_ok=True)
        params.write_text(json.dumps({'commands': [body], 'executionTimeout': ['10800']}))
        result = aws('ssm', 'send-command', '--instance-ids', instance, '--document-name',
                     'AWS-RunShellScript' if host in LINUX else 'AWS-RunPowerShellScript',
                     '--timeout-seconds', '600', '--parameters', 'file://' + str(params))
        cid = result['Command']['CommandId']
        record = {'id': cid, 'instance': instance, 'host': host, 'script': str(script), 'extra': extra,
                  'scriptSha256': hashlib.sha256(body.encode()).hexdigest(), 'sentAt': dt.datetime.now(dt.timezone.utc).isoformat()}
        (ROOT / 'commands').mkdir(exist_ok=True)
        (ROOT / 'commands' / (cid + '.json')).write_text(json.dumps(record))
        with (ROOT / 'commands.jsonl').open('a') as f:
            f.write(json.dumps(record) + '\n')
        print(cid)
    elif action in ('result', 'wait'):
        record = json.loads((ROOT / 'commands' / (sys.argv[2] + '.json')).read_text())
        check_instance(state, record['host'], states=('running', 'stopped', 'stopping', 'pending'))
        while True:
            try:
                r = aws('ssm', 'get-command-invocation', '--command-id', record['id'], '--instance-id', record['instance'])
            except RuntimeError as e:
                if 'InvocationDoesNotExist' in str(e) and action == 'wait':
                    time.sleep(3)
                    continue
                raise
            if r['Status'] in ('Success', 'Failed', 'TimedOut', 'Cancelled') or action == 'result':
                break
            time.sleep(5)
        if r['Status'] in ('Success', 'Failed', 'TimedOut', 'Cancelled'):
            (ROOT / 'results').mkdir(exist_ok=True)
            (ROOT / 'results' / (record['id'] + '.json')).write_text(json.dumps(r, indent=2))
        print(json.dumps({'Status': r['Status'], 'ResponseCode': r.get('ResponseCode')}))
        print(r.get('StandardOutputContent', ''))
        if r.get('StandardErrorContent'):
            print('STDERR:', r['StandardErrorContent'][-3000:])
    elif action == 'instances':
        ids = [state['outputs'][h] for h in HOSTS if h in state.get('outputs', {})]
        for i in aws('ec2', 'describe-instances', '--instance-ids', *ids)['Reservations']:
            for x in i['Instances']:
                tags = {t['Key']: t['Value'] for t in x.get('Tags', [])}
                print(x['InstanceId'], tags.get('Name'), x['State']['Name'], x['InstanceType'], x.get('PrivateIpAddress'), tags.get('RunId'))
    elif action == 'power':
        # power HOST stop-force|start|reboot ; explicit, ownership-checked.
        host, op = sys.argv[2:4]
        instance = check_instance(state, host, states=('running', 'stopped'))
        if op == 'stop-force':
            print(aws('ec2', 'stop-instances', '--instance-ids', instance, '--force'))
        elif op == 'start':
            print(aws('ec2', 'start-instances', '--instance-ids', instance))
        elif op == 'reboot':
            print(aws('ec2', 'reboot-instances', '--instance-ids', instance))
        elif op == 'terminate':
            print(aws('ec2', 'terminate-instances', '--instance-ids', instance))
        else:
            raise ValueError(op)
    else:
        raise ValueError(action)


if __name__ == '__main__':
    main()
