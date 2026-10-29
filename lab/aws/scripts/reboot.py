"""Reboot exact, tag-checked lab hosts; record timing without retrieving credentials."""
import argparse
import json
from pathlib import Path
import time
from lab import aws,verify_account
from ssm import HOSTS,verify_host

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('hosts',nargs='+',choices=HOSTS);p.add_argument('--state',type=Path,required=True);p.add_argument('--profile',default='homelab-admin');a=p.parse_args()
    state=json.loads(a.state.read_text());verify_account(a.profile,state['region'],state['account'])
    call=lambda *args:aws(a.profile,state['region'],*args)
    ids=[state['outputs'][host+'Id'] for host in a.hosts]
    found=call('ec2','describe-instances','--instance-ids',*ids)
    instances=[i for reservation in found['Reservations'] for i in reservation['Instances']]
    if {i['InstanceId'] for i in instances}!=set(ids):raise ValueError('Incomplete inventory')
    for instance in instances:verify_host(instance,state)
    record={'phase':'reboot','hosts':a.hosts,'instanceIds':ids,'requestedAt':time.time()}
    call('ec2','reboot-instances','--instance-ids',*ids)
    with (a.state.parent/'reboots.jsonl').open('a') as stream:stream.write(json.dumps(record)+'\n')
    print(json.dumps(record))
if __name__=='__main__':main()
