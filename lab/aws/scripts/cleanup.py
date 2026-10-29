"""Delete this run's stack and separately-created secrets; audit chargeable leftovers."""
import argparse
import json
from pathlib import Path
import time
from lab import aws,verify_account,verify_stack


def verify_secret(secret,run_id):
    prefix='bower-lab/'+run_id+'/'
    tags={entry['Key']:entry['Value'] for entry in secret.get('Tags',[])}
    if not secret['Name'].startswith(prefix) or secret['Name'][len(prefix):] not in ('Collector','Linux1','Linux2','Wec','Windows1','Windows2','corpus'):
        raise ValueError('Secret is outside the exact run inventory')
    if tags.get('Project')!='bower-lab' or tags.get('RunId')!=run_id:
        raise ValueError('Secret tags do not match the run')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',type=Path,required=True);p.add_argument('--profile',default='homelab-admin');p.add_argument('--apply',action='store_true');a=p.parse_args()
    state=json.loads(a.state.read_text());verify_account(a.profile,state['region'],state['account'])
    call=lambda *args:aws(a.profile,state['region'],*args)
    stack=call('cloudformation','describe-stacks','--stack-name',state['stack'])['Stacks'][0];verify_stack(stack,state['runId'])
    instances=call('ec2','describe-instances','--filters','Name=tag:Project,Values=bower-lab','Name=tag:RunId,Values='+state['runId'])
    hosts=[i for r in instances['Reservations'] for i in r['Instances']]
    volumes=sorted({d['Ebs']['VolumeId'] for i in hosts for d in i.get('BlockDeviceMappings',[])})
    secrets=call('secretsmanager','list-secrets','--filters',json.dumps([{'Key':'name','Values':['bower-lab/'+state['runId']+'/']}]))['SecretList']
    for secret in secrets:verify_secret(secret,state['runId'])
    inventory={'stack':state['stack'],'runId':state['runId'],'instanceIds':[i['InstanceId'] for i in hosts],'volumeIds':volumes,'secrets':[s['Name'] for s in secrets],'retainedBucket':state['outputs']['Bucket']}
    (a.state.parent/'cleanup-inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
    print(json.dumps({'action':'delete' if a.apply else 'plan',**inventory}),flush=True)
    if not a.apply:return
    # Delete only secrets created for this disposable run, after checking names and tags.
    for secret in secrets:call('secretsmanager','delete-secret','--secret-id',secret['ARN'],'--force-delete-without-recovery')
    call('cloudformation','delete-stack','--stack-name',stack['StackId'])
    # The AWS waiter is bounded; stdout stays metadata-only. The caller can monitor separately.
    call('cloudformation','wait','stack-delete-complete','--stack-name',stack['StackId'])
    filters=['Name=tag:Project,Values=bower-lab','Name=tag:RunId,Values='+state['runId']]
    remaining_hosts=[i for r in call('ec2','describe-instances','--filters',*filters)['Reservations'] for i in r['Instances'] if i['State']['Name']!='terminated']
    remaining_volumes=call('ec2','describe-volumes','--filters','Name=volume-id,Values='+','.join(volumes))['Volumes'] if volumes else []
    vpc=state['outputs']['VpcId']
    endpoints=call('ec2','describe-vpc-endpoints','--filters','Name=vpc-id,Values='+vpc)['VpcEndpoints']
    nats=[n for n in call('ec2','describe-nat-gateways','--filter','Name=vpc-id,Values='+vpc)['NatGateways'] if n['State']!='deleted']
    addresses=call('ec2','describe-addresses','--filters',*filters)['Addresses']
    remaining_secrets=call('secretsmanager','list-secrets','--filters',json.dumps([{'Key':'name','Values':['bower-lab/'+state['runId']+'/']}]))['SecretList']
    report={'phase':'cleanup','runId':state['runId'],'checkedAt':time.time(),'stackDeleted':True,'remainingInstances':len(remaining_hosts),'remainingVolumes':len(remaining_volumes),'remainingEndpoints':len(endpoints),'remainingNatGateways':len(nats),'remainingElasticIps':len(addresses),'remainingSecrets':len(remaining_secrets),'retainedBucket':state['outputs']['Bucket'],'bucketExpiryDays':90}
    report['status']='passed' if not any(report[k] for k in ('remainingInstances','remainingVolumes','remainingEndpoints','remainingNatGateways','remainingElasticIps','remainingSecrets')) else 'failed'
    target=a.state.parent/'cleanup.json';target.write_text(json.dumps(report,indent=2)+'\n')
    call('s3api','put-object','--bucket',state['outputs']['Bucket'],'--key','runs/'+state['runId']+'/report/cleanup.json','--body',str(target))
    print(json.dumps(report))
    if report['status']!='passed':raise SystemExit(1)

if __name__=='__main__':main()
