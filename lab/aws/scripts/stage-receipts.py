"""Stage metadata-only producer receipts where the verifier's existing role can read them."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
from lab import aws,verify_account

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',required=True,type=Path);p.add_argument('--profile',default='homelab-admin');a=p.parse_args()
    state=json.loads(a.state.read_text());region=state['region'];bucket=state['outputs']['Bucket']
    verify_account(a.profile,region,state['account'])
    call=lambda *args:aws(a.profile,region,*args)
    objects=call('s3api','list-objects-v2','--bucket',bucket,'--prefix','runs/'+state['runId']+'/hosts/').get('Contents',[])
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);receipts=[]
        for obj in objects:
            key=obj['Key']
            if not (key.endswith('.acks.json') or key.endswith('/native.json')):continue
            target=root/'download.json'
            call('s3api','get-object','--bucket',bucket,'--key',key,str(target))
            receipts.append([key.split('/')[-2],Path(key).name,json.loads(target.read_text())])
        if {r[0] for r in receipts}!={'Collector','Linux1','Linux2','Wec','Windows1','Windows2'}:raise ValueError('Receipts missing for a source')
        target=root/'receipts.json';target.write_text(json.dumps(receipts))
        call('s3api','put-object','--bucket',bucket,'--key','artifacts/receipts.json','--body',str(target))
        print(json.dumps({'receiptFiles':len(receipts),'events':sum(len(r[2].get('acknowledged',r[2].get('correlations',[]))) for r in receipts)}))
if __name__=='__main__':main()
