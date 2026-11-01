#!/usr/bin/env bash
# Native restoration control only: an empty table, no traffic block or hour claim.
set -euo pipefail
umask 077
python3 - <<'PY'
import datetime as dt,hashlib,json,os,subprocess,time,types
from pathlib import Path
run=os.environ['BOWER_LAB_RUN'];bucket=os.environ['BOWER_LAB_BUCKET']
assert run=='bower-ws6-20261101-011000'
digest='3d9daae5bd9e2b258dda6aa32045b3baa3c39b92a7e1224be7c8d8a4e9d6e4d9'
table='bower_guard_control_'+digest[:16];root=Path('/var/lib/bower-lab')/table
root.mkdir(mode=0o700)
source=root/'helper.sh'
def call(*args):return subprocess.run(args,capture_output=True,check=True,timeout=60)
call('aws','--region','ap-southeast-2','s3','cp','s3://'+bucket+'/artifacts/guard-'+digest+'.sh',str(source),'--only-show-errors')
assert hashlib.sha256(source.read_bytes()).hexdigest()==digest
code=source.read_text().split("python3 - <<'PY'\n",1)[1].rsplit('\nPY',1)[0]
module=types.ModuleType('guard_control_source');exec(compile(code,'reviewed-helper','exec'),module.__dict__)
scope={'runId':run,'planSha256':digest,'table':table,'ownerComment':run+':'+digest,'bucket':bucket,'resultPrefix':'results/guard-control/'+digest}
existing=json.loads(call('nft','-j','list','tables').stdout)
assert not any(x.get('table',{}).get('name')==table for x in existing['nftables'])
created=False
try:
    subprocess.run(['nft','-f','-'],input=('table inet '+table+' { comment "'+scope['ownerComment']+'"; }\n').encode(),capture_output=True,timeout=30,check=True)
    created=True
    listing=json.loads(call('nft','-j','list','table','inet',table).stdout)
    entries=[x for x in listing['nftables'] if 'metainfo' not in x]
    assert len(entries)==1 and entries[0]['table']['name']==table
    scope['tableSnapshotSha256']=hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    (root/'scope.json').write_text(json.dumps(scope))
    (root/'applied.json').write_text(json.dumps({'appliedMonotonic':time.monotonic(),'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))
    (root/'restore.py').write_text(module.RESTORE)
    unit=table.replace('_','-')
    call('systemd-run','--unit='+unit,'--on-active=15s','--timer-property=AccuracySec=1s','--property=Type=oneshot','/usr/bin/python3',str(root/'restore.py'),str(root))
    deadline=time.monotonic()+90
    while not (root/'restored.json').exists() and time.monotonic()<deadline:time.sleep(1)
    result=json.loads((root/'restored.json').read_text())
    tables=json.loads(call('nft','-j','list','tables').stdout)['nftables']
    absent=not any(x.get('table',{}).get('name')==table for x in tables)
    assert result['removed'] and absent and result['bootUnchanged'] and not result['minimumDurationPassed']
    assert result['ownershipCheck']=='exact-installed-table-snapshot'
    report={'schemaVersion':1,'runId':run,'testedAt':dt.datetime.now(dt.timezone.utc).isoformat(),'helperSha256':digest,'recordType':'native-empty-table-restoration-control','trafficBlocked':False,'oneHourOutageQualified':False,'tableCommentInJson':'comment' in entries[0]['table'],'tableAbsent':absent,'guardControlPassed':True,'restoration':result}
    (root/'control.json').write_text(json.dumps(report))
    call('aws','--region','ap-southeast-2','s3','cp',str(root/'control.json'),'s3://'+bucket+'/'+scope['resultPrefix']+'/control.json','--sse','AES256','--only-show-errors')
    print(json.dumps(report))
finally:
    if created:
        remaining=json.loads(call('nft','-j','list','tables').stdout)['nftables']
        if any(x.get('table',{}).get('name')==table for x in remaining):call('nft','delete','table','inet',table)
PY
