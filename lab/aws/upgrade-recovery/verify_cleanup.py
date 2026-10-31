"""Independent cleanup audit for RunId bower-ws4-20261031-074918 (queries only, metadata output)."""
import datetime as dt
import json
import os
import subprocess

RUN = os.environ['BOWER_LAB_RUN_ID']  # bower-ws4-UTCyyyymmdd-HHMMSS
state = json.load(open(os.environ['BOWER_LAB_DIR'] + '/state.json'))
azs = json.load(open(os.environ['BOWER_LAB_DIR'] + '/azure/azure-state.json'))


def aws(*a, ok=False):
    r = subprocess.run(['aws', '--profile', 'homelab-admin', '--region', 'ap-southeast-2', *a, '--output', 'json'], capture_output=True, text=True)
    if r.returncode:
        if ok:
            return {'error': r.stderr.strip()[-300:]}
        raise SystemExit(r.stderr)
    return json.loads(r.stdout) if r.stdout.strip() else {}


def az(*a, ok=False):
    r = subprocess.run(['az', *a, '-o', 'json'], capture_output=True, text=True)
    if r.returncode:
        if ok:
            return {'error': r.stderr.strip()[-300:]}
        raise SystemExit(r.stderr)
    return json.loads(r.stdout) if r.stdout.strip() else None


checks = {}
tag = ['Name=tag:RunId,Values=' + RUN]
checks['awsAccount'] = aws('sts', 'get-caller-identity')['Account']
stack = aws('cloudformation', 'describe-stacks', '--stack-name', state['stackId'])['Stacks'][0]
checks['stack'] = {'status': stack['StackStatus'], 'pass': stack['StackStatus'] == 'DELETE_COMPLETE'}
inst = [x for r in aws('ec2', 'describe-instances', '--filters', *tag)['Reservations'] for x in r['Instances']]
checks['instances'] = {'states': sorted({x['InstanceId']: x['State']['Name'] for x in inst}.items()), 'pass': all(x['State']['Name'] == 'terminated' for x in inst)}
ids = [state['outputs'][h] for h in ['Dc', 'Wec', 'Wec2', 'Linux', 'Linux2']]
by_id = [x for r in aws('ec2', 'describe-instances', '--instance-ids', *ids)['Reservations'] for x in r['Instances']]
checks['instancesById'] = {'pass': all(x['State']['Name'] == 'terminated' for x in by_id), 'count': len(by_id)}
vols = aws('ec2', 'describe-volumes', '--filters', *tag)['Volumes']
checks['volumes'] = {'remaining': [v['VolumeId'] for v in vols], 'pass': not vols}
snaps = aws('ec2', 'describe-snapshots', '--owner-ids', 'self', '--filters', *tag)['Snapshots']
checks['snapshots'] = {'remaining': [s['SnapshotId'] for s in snaps], 'pass': not snaps}
amis = aws('ec2', 'describe-images', '--owners', 'self', '--filters', *tag)['Images']
checks['images'] = {'remaining': [i['ImageId'] for i in amis], 'pass': not amis}
sgs = aws('ec2', 'describe-security-groups', '--filters', *tag)['SecurityGroups']
checks['securityGroups'] = {'remaining': [g['GroupId'] for g in sgs], 'pass': not sgs}
subnets = aws('ec2', 'describe-subnets', '--filters', *tag)['Subnets']
checks['subnets'] = {'remaining': [s['SubnetId'] for s in subnets], 'pass': not subnets}
rts = aws('ec2', 'describe-route-tables', '--filters', *tag)['RouteTables']
checks['routeTables'] = {'remaining': [r['RouteTableId'] for r in rts], 'pass': not rts}
enis = aws('ec2', 'describe-network-interfaces', '--filters', 'Name=subnet-id,Values=' + state['outputs']['Subnet'])['NetworkInterfaces']
checks['networkInterfacesInSubnet'] = {'remaining': [e['NetworkInterfaceId'] for e in enis], 'pass': not enis}
roles = [r['RoleName'] for r in aws('iam', 'list-roles')['Roles'] if RUN in r['RoleName']]
checks['iamRoles'] = {'remaining': roles, 'pass': not roles}
profiles = [p['InstanceProfileName'] for p in aws('iam', 'list-instance-profiles')['InstanceProfiles'] if RUN in p['InstanceProfileName']]
checks['instanceProfiles'] = {'remaining': profiles, 'pass': not profiles}
secrets = aws('secretsmanager', 'list-secrets', '--include-planned-deletion', '--filters', 'Key=tag-value,Values=' + RUN)['SecretList']
checks['secrets'] = {'remaining': [{'name': s['Name'], 'deletedDate': str(s.get('DeletedDate'))} for s in secrets],
                     'pass': all(s.get('DeletedDate') for s in secrets),
                     'note': 'CloudFormation schedules stack secrets for deletion; a scheduled-deletion secret is not billed'}
bucket = aws('s3api', 'head-bucket', '--bucket', state['outputs']['Artifacts'], ok=True)
checks['bucket'] = {'headBucket': 'absent' if 'error' in bucket else 'present', 'pass': 'error' in bucket and ('404' in bucket['error'] or 'Not Found' in bucket['error'])}
sched = aws('scheduler', 'get-schedule', '--name', RUN + '-expiry', ok=True)
checks['expirySchedule'] = {'pass': 'error' in sched and 'ResourceNotFound' in sched['error']}
logs = aws('logs', 'describe-log-groups', '--log-group-name-prefix', '/', ok=True)
groups = [g['logGroupName'] for g in logs.get('logGroups', []) if RUN in g['logGroupName']] if isinstance(logs, dict) else []
checks['logGroups'] = {'remaining': groups, 'pass': not groups}
# Azure
acct = az('account', 'show')
checks['azureSubscription'] = acct['id'] == azs['subscription'] and acct['tenantId'] == azs['tenant']
exists = az('group', 'exists', '-n', azs['group'])
checks['azureResourceGroup'] = {'exists': exists, 'pass': exists is False}
deleted_ws = az('monitor', 'log-analytics', 'workspace', 'list-deleted-workspaces', ok=True) or []
names = [w.get('name') for w in deleted_ws] if isinstance(deleted_ws, list) else []
checks['workspaceSoftDeleted'] = {'present': azs['workspaceName'] in names, 'pass': azs['workspaceName'] not in names}
apps = az('ad', 'app', 'list', '--filter', f"startswith(displayName,'{RUN}')") or []
checks['entraApps'] = {'remaining': [a['displayName'] for a in apps], 'pass': not apps}
sps = az('ad', 'sp', 'list', '--filter', f"startswith(displayName,'{RUN}')") or []
checks['servicePrincipals'] = {'remaining': [s['displayName'] for s in sps], 'pass': not sps}
for kind in ['application', 'servicePrincipal']:
    d = az('rest', '--method', 'get', '--url', f"https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.{kind}?$filter=startswith(displayName,'{RUN}')", ok=True) or {}
    left = [x['displayName'] for x in d.get('value', [])]
    checks['deleted_' + kind] = {'remaining': left, 'pass': not left}
principals = {i['principalId'] for i in azs['identities'].values()}
listed = az('role', 'assignment', 'list', '--all', '--include-inherited', '--subscription', azs['subscription'])
ra = [a['id'] for a in listed if a.get('principalId') in principals or azs['group'] in a.get('scope', '')]
checks['roleAssignments'] = {'remaining': ra, 'scanned': len(listed), 'pass': not ra}
result = {'run': RUN, 'auditedAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'checks': checks,
          'allPassed': all((v.get('pass') if isinstance(v, dict) else v) is True for k, v in checks.items() if k != 'awsAccount')}
print(json.dumps(result, indent=1, default=str))
