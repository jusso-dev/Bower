#!/usr/bin/env python3
"""Read-only absence checks against the reviewed final-campaign inventory."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path('/private/tmp/bower-final-qualification')
ACCOUNT = '959038055523'
SUB = '945092a0-2500-4b25-85a4-99f1c3135906'
TENANT = 'f4f33fb1-b681-40d1-a854-6f888d45b891'
RUN = 'bower-ws6-20261101-011000'
PLAN_SHA256 = 'daf0efcd316034b79207a6fa4fa375ec3b30c1ea33a1358e275350a223d2151e'


def command(argv, missing=()):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if result.returncode:
        match = re.search(r'An error occurred \(([^)]+)\)', result.stderr)
        code = match.group(1) if match else 'command-error'
        if code in missing:
            return None
        # Error text may contain identifiers or unexpected service payloads.
        raise RuntimeError(code)
    return json.loads(result.stdout) if result.stdout.strip() else None


def aws(*args, missing=()):
    return command(['aws', '--profile', 'homelab-admin', '--region', 'ap-southeast-2',
                    *args, '--output', 'json'], missing)


def az(*args):
    return command(['az', *args, '--only-show-errors', '--output', 'json'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if hashlib.sha256((ROOT / 'verify-final-cleanup.py').read_bytes()).hexdigest() != '031e390e115a76125098da613e569d9e29892690479eac3074d82024575e4d9f':
        raise ValueError('original-reviewed-verifier-changed')
    plan_path = ROOT / 'cleanup-plan.json'
    plan_bytes = plan_path.read_bytes()
    if hashlib.sha256(plan_bytes).hexdigest() != PLAN_SHA256:
        raise ValueError('reviewed-inventory-changed')
    plan = json.loads(plan_bytes)
    a, z = plan['aws'], plan['azure']
    if a['account'] != ACCOUNT or a['region'] != 'ap-southeast-2' or z['subscription'] != SUB or z['tenant'] != TENANT:
        raise ValueError('inventory-scope')
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise ValueError('aws-account')
    account = az('account', 'show')
    if account['id'] != SUB or account['tenantId'] != TENANT:
        raise ValueError('azure-account')
    stack_id = a['stackId']
    if not stack_id.startswith('arn:aws:cloudformation:ap-southeast-2:' + ACCOUNT + ':stack/' + RUN + '/'):
        raise ValueError('stack-scope')
    if len(a['instances']) != 3 or any(i['tags'].get('RunId') != RUN or i['tags'].get('Project') != 'bower-lab' for i in a['instances']):
        raise ValueError('instance-scope')
    result = {'schemaVersion': 1, 'recordType': 'independent-final-cleanup-verification',
              'runId': RUN, 'startedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
              'inventoryPlanSha256': PLAN_SHA256,
              'account': ACCOUNT, 'subscription': SUB, 'tenant': TENANT,
              'checks': [], 'preservationChecks': [],
              'verifierRevision': 'original checks plus narrowly verified aged Windows instance absence',
              'originalVerifierSha256': '031e390e115a76125098da613e569d9e29892690479eac3074d82024575e4d9f',
              'scope': 'Exact session-owned resources from the reviewed plan; shared infrastructure is outside removal scope and checked for presence separately.'}

    def check(name, operation):
        try:
            evidence, passed = operation()
            result['checks'].append({'check': name, 'passed': bool(passed), 'evidence': evidence})
        except Exception as error:
            result['checks'].append({'check': name, 'passed': False, 'errorCategory': type(error).__name__})

    def stack():
        found = aws('cloudformation', 'describe-stacks', '--stack-name', stack_id)['Stacks']
        statuses = [s['StackStatus'] for s in found if s['StackId'] == stack_id]
        return {'stackId': stack_id, 'statuses': statuses}, statuses == ['DELETE_COMPLETE']

    check('aws-stack', stack)
    instance_ids = sorted(i['id'] for i in a['instances'])

    def instances():
        reservations = aws('ec2', 'describe-instances', '--instance-ids', *instance_ids)['Reservations']
        values = {i['InstanceId']: i['State']['Name'] for r in reservations for i in r['Instances']}
        missing = set(instance_ids) - set(values)
        evidence = {'states': values, 'absentAfterVerifiedRetirement': []}
        if not set(values) <= set(instance_ids) or any(v != 'terminated' for v in values.values()):
            return evidence, False
        if missing:
            # EC2 stops returning older terminated instance records. This narrow
            # supplement permits only the independently retired Windows host,
            # with both exact-ID and filtered successful empty API responses.
            retired_id = 'i-058c97f8db6c0dbbf'
            if missing != {retired_id}:
                return evidence, False
            retirement_path = ROOT / 'wec/windows-host-retirement-verified.json'
            retirement_hash = '638c6dfb46d5e7eeaadd85098c65314a0ff1ab7c7f710679201432a07cbe292e'
            if hashlib.sha256(retirement_path.read_bytes()).hexdigest() != retirement_hash:
                raise ValueError('prior-retirement-proof-changed')
            retirement = json.loads(retirement_path.read_text())
            if (retirement['runId'] != RUN or retirement['account'] != ACCOUNT
                    or retirement['region'] != 'ap-southeast-2'
                    or retirement['instance'] != {'id': retired_id, 'state': 'terminated'}
                    or retirement['windowsComputeAndVolumeRemoved'] is not True):
                raise ValueError('prior-retirement-scope')
            exact = aws('ec2', 'describe-instances', '--instance-ids', retired_id)['Reservations']
            filtered = aws('ec2', 'describe-instances', '--filters', 'Name=instance-id,Values=' + retired_id)['Reservations']
            if exact or filtered:
                return evidence, False
            evidence.update(absentAfterVerifiedRetirement=[retired_id],
                            exactIdQuerySucceededAndEmpty=True,
                            filteredQuerySucceededAndEmpty=True,
                            priorRetirementProofSha256=retirement_hash)
        return evidence, set(values) | missing == set(instance_ids)

    check('aws-instances', instances)
    volume_ids = sorted(v['id'] for v in a['volumes'])

    def volumes():
        values = aws('ec2', 'describe-volumes', '--filters', 'Name=volume-id,Values=' + ','.join(volume_ids))['Volumes']
        ids = [v['VolumeId'] for v in values]
        return {'expectedAbsent': volume_ids, 'remaining': ids}, not ids

    if not volume_ids:
        raise ValueError('missing-volume-inventory')
    check('aws-volumes', volumes)
    for name, operation, key, id_key, extra in (
        ('snapshots', 'describe-snapshots', 'Snapshots', 'SnapshotId', ('--owner-ids', 'self')),
        ('images', 'describe-images', 'Images', 'ImageId', ('--owners', 'self')),
        ('elastic-ips', 'describe-addresses', 'Addresses', 'AllocationId', ()),
        ('vpc-endpoints', 'describe-vpc-endpoints', 'VpcEndpoints', 'VpcEndpointId', ()),
    ):
        def tagged(operation=operation, key=key, id_key=id_key, extra=extra):
            values = aws('ec2', operation, *extra, '--filters', 'Name=tag:RunId,Values=' + RUN)[key]
            ids = [v[id_key] for v in values]
            return {'runId': RUN, 'remaining': ids}, not ids
        check('aws-run-tagged-' + name, tagged)
    buckets = [b['name'] for b in a['retainedBuckets']]
    if len(buckets) != 1 or not buckets[0].startswith(RUN + '-artifacts-'):
        raise ValueError('bucket-scope')

    def bucket_absence():
        existing = {b['Name'] for b in aws('s3api', 'list-buckets')['Buckets']}
        remaining = sorted(set(buckets) & existing)
        return {'expectedAbsent': buckets, 'remaining': remaining}, not remaining

    check('aws-retained-buckets', bucket_absence)
    for resource in a['stackResourcesToRemove']:
        kind, identity = resource['ResourceType'], resource['PhysicalResourceId']
        if kind == 'AWS::IAM::Role':
            check('aws-role:' + identity, lambda identity=identity: ({'role': identity}, aws('iam', 'get-role', '--role-name', identity, missing=('NoSuchEntity',)) is None))
        elif kind == 'AWS::IAM::InstanceProfile':
            check('aws-profile:' + identity, lambda identity=identity: ({'profile': identity}, aws('iam', 'get-instance-profile', '--instance-profile-name', identity, missing=('NoSuchEntity',)) is None))
        elif kind == 'AWS::Scheduler::Schedule':
            name = identity.rsplit('/', 1)[-1]
            check('aws-expiry-schedule', lambda name=name: ({'schedule': name}, aws('scheduler', 'get-schedule', '--name', name, missing=('ResourceNotFoundException',)) is None))
        elif kind in ('AWS::EC2::SecurityGroup', 'AWS::EC2::Subnet', 'AWS::EC2::RouteTable'):
            operation, key, filter_name, id_key = {
                'AWS::EC2::SecurityGroup': ('describe-security-groups', 'SecurityGroups', 'group-id', 'GroupId'),
                'AWS::EC2::Subnet': ('describe-subnets', 'Subnets', 'subnet-id', 'SubnetId'),
                'AWS::EC2::RouteTable': ('describe-route-tables', 'RouteTables', 'route-table-id', 'RouteTableId'),
            }[kind]

            def network(operation=operation, key=key, filter_name=filter_name, id_key=id_key, identity=identity):
                values = aws('ec2', operation, '--filters', 'Name=' + filter_name + ',Values=' + identity)[key]
                remaining = [v[id_key] for v in values]
                return {'expectedAbsent': identity, 'remaining': remaining}, not remaining

            check(kind + ':' + identity, network)

    group_id = z['group']['id']
    group = group_id.rsplit('/', 1)[-1]
    if not group_id.lower().startswith('/subscriptions/' + SUB + '/resourcegroups/rg-bower-val-'):
        raise ValueError('group-scope')
    check('azure-resource-group', lambda: ({'resourceGroup': group}, az('group', 'exists', '--name', group, '--subscription', SUB) is False))

    def resources():
        values = az('resource', 'list', '--subscription', SUB)
        remaining = [v['id'] for v in values if v.get('resourceGroup', '').lower() == group.lower()]
        return {'resourceGroup': group, 'remaining': remaining}, not remaining

    check('azure-resources', resources)
    for identity in z['identities']:
        app_id = identity['application']['appId']
        if not re.fullmatch(r'[a-f0-9-]{36}', app_id):
            raise ValueError('application-scope')
        for kind in ('app', 'sp'):

            def directory(kind=kind, app_id=app_id):
                values = az('ad', kind, 'list', '--filter', "appId eq '" + app_id + "'")
                remaining = [v['id'] for v in values]
                return {'applicationId': app_id, 'remaining': remaining}, not remaining

            check('azure-' + kind + ':' + identity['role'], directory)
    grants = {g['id'].lower() for identity in z['identities'] for g in identity['roleAssignments']}

    def assignments():
        values = az('role', 'assignment', 'list', '--all', '--subscription', SUB)
        remaining = [v['id'] for v in values if v['id'].lower() in grants]
        return {'expectedAbsentCount': len(grants), 'remaining': remaining}, not remaining

    check('azure-role-assignments', assignments)
    shared = a['preserveShared']

    def preserve(name, operation):
        try:
            evidence, passed = operation()
            result['preservationChecks'].append({'check': name, 'passed': bool(passed), 'evidence': evidence})
        except Exception as error:
            result['preservationChecks'].append({'check': name, 'passed': False, 'errorCategory': type(error).__name__})

    def shared_vpc():
        values = aws('ec2', 'describe-vpcs', '--vpc-ids', shared['vpcId'])['Vpcs']
        states = {v['VpcId']: v['State'] for v in values}
        return states, states == {shared['vpcId']: 'available'}

    def shared_nat():
        values = aws('ec2', 'describe-nat-gateways', '--nat-gateway-ids', *shared['natGatewayIds'])['NatGateways']
        states = {v['NatGatewayId']: v['State'] for v in values}
        return states, states == {identity: 'available' for identity in shared['natGatewayIds']}

    def shared_routes():
        values = aws('ec2', 'describe-route-tables', '--route-table-ids', *shared['routeTableIds'])['RouteTables']
        ids = sorted(v['RouteTableId'] for v in values)
        return {'present': ids}, ids == sorted(shared['routeTableIds'])

    preserve('shared-vpc-present', shared_vpc)
    preserve('shared-nat-present', shared_nat)
    preserve('shared-route-tables-present', shared_routes)
    result['checkedAt'] = dt.datetime.now(dt.timezone.utc).isoformat()
    result['allCheckedResourcesAbsent'] = all(c['passed'] for c in result['checks'])
    result['sharedInfrastructurePresent'] = all(c['passed'] for c in result['preservationChecks'])
    result['cleanupVerified'] = result['allCheckedResourcesAbsent'] and result['sharedInfrastructurePresent']
    result['limitations'] = ['This is not an account-wide all-region billing audit.',
                             'Stack deletion covers stack-owned route associations; shared VPC/NAT infrastructure is intentionally preserved.',
                             'Private staging-file removal is verified separately.']
    with args.output.open('x') as target:
        json.dump(result, target, indent=2)
        target.write('\n')
    print(json.dumps({'evidence': str(args.output), 'passed': result['cleanupVerified'],
                      'checks': len(result['checks']), 'sharedPresenceChecks': len(result['preservationChecks']),
                      'failedChecks': [c['check'] for c in result['checks'] + result['preservationChecks'] if not c['passed']]}))
    return 0 if result['cleanupVerified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

