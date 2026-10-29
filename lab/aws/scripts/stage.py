"""Upload an explicit public artifact allow-list and hash manifest for one lab run."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
from lab import aws,verify_account,verify_stack


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('state','artifacts'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('version','source-commit','artifact-commit'):p.add_argument('--'+name,required=True)
    p.add_argument('--artifact-run',required=True,type=int);p.add_argument('--profile',default='homelab-admin');a=p.parse_args()
    state=json.loads(a.state.read_text());verify_account(a.profile,state['region'],state['account'])
    call=lambda *args:aws(a.profile,state['region'],*args)
    stack=call('cloudformation','describe-stacks','--stack-name',state['stack'])['Stacks'][0];verify_stack(stack,state['runId'])
    scripts=Path(__file__).resolve().parent;a.artifacts.mkdir(parents=True,exist_ok=True)
    for name in ('control.py','node.py','load.py','verify.py'):shutil.copyfile(scripts/name,a.artifacts/name)
    with tarfile.open(a.artifacts/'lab-pack.tar.gz','w:gz') as archive:
        archive.add(scripts.parent/'packs/windows-lab',arcname='.')
    names=('collector.rpm','collector.msi','management.tar.gz','cli.tar.gz','lab-pack.tar.gz','control.py','node.py','load.py','verify.py')
    files={name:hashlib.sha256((a.artifacts/name).read_bytes()).hexdigest() for name in names}
    hosts={name:{'id':state['outputs'][name+'Id'],'ip':state['outputs'][name+'Ip']} for name in ('Control','Collector','Linux1','Linux2','Wec','Windows1','Windows2')}
    manifest={'runId':state['runId'],'account':state['account'],'version':a.version,'sourceCommit':a.source_commit,'artifactCommit':a.artifact_commit,'artifactRun':a.artifact_run,'signedPackages':False,'hosts':hosts,'files':files}
    (a.artifacts/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    for name in (*names,'manifest.json'):
        call('s3api','put-object','--bucket',state['outputs']['Bucket'],'--key','artifacts/'+name,'--body',str(a.artifacts/name))
    print(json.dumps({'runId':state['runId'],'uploadedFiles':len(names)+1,'signedPackages':False}))
if __name__=='__main__':main()
