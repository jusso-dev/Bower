#!/bin/bash
set -euo pipefail
umask 077
# Independent cleanup survives interruption of this SSM command.
test -f /var/lib/bower/.lab-volume
mountpoint -q /var/lib/bower
systemd-run --unit=bower-lab-disk-recover --on-active=60s /usr/bin/rm -f /var/lib/bower/.lab-disk-fill >/dev/null
python3 - <<'PY'
from collections import Counter
import json,os,sys,time,subprocess
from pathlib import Path
sys.path.insert(0,'/opt/bower-lab')
import load
root=Path('/var/lib/bower');fill=root/'.lab-disk-fill'
stat=os.statvfs(root);capacity=stat.f_blocks*stat.f_frsize
if not 3*1024**3<capacity<5*1024**3 or root.stat().st_dev==Path('/').stat().st_dev:
    raise ValueError('Not the isolated 4GiB queue volume')
corpus=json.loads(load.aws('secretsmanager','get-secret-value','--secret-id','bower-lab/'+load.RUN+'/corpus')['SecretString'])
outcomes=Counter();acks=[];started=time.monotonic()
try:
    with fill.open('xb') as stream:
        os.posix_fallocate(stream.fileno(),0,stat.f_bavail*stat.f_frsize)
    remaining=os.statvfs(root).f_bavail*stat.f_frsize
    for index in range(1,101):
        item=load.event(index,'disk',0,0,corpus)
        payload=json.loads(item[1]);payload['attributes']['labPadding']='x'*16000
        status=load.send((item[0],json.dumps(payload).encode(),False))[1]
        outcomes[str(status)]+=1
        if status in (200,202):acks.append(item[0])
        if time.monotonic()-started>25:break
finally:
    fill.unlink(missing_ok=True)
report={'phase':'disk-pressure','httpStatuses':dict(outcomes),'acknowledged':len(acks),'freeBytesWhileFilled':remaining,
    'durationSeconds':time.monotonic()-started,'fillRemoved':not fill.exists(),'expectedBackpressure':outcomes['503']>0,
    'unexpectedErrors':sum(v for k,v in outcomes.items() if k not in ('202','200','503'))}
report['status']='passed' if report['expectedBackpressure'] and report['unexpectedErrors']==0 else 'failed'
results=Path('/opt/bower-lab/results');(results/'disk.json').write_text(json.dumps(report));(results/'disk.acks.json').write_text(json.dumps({'acknowledged':acks,'denied':[]}))
for name in ('disk.json','disk.acks.json'):
    subprocess.run(['aws','s3','cp',str(results/name),'s3://'+load.BUCKET+'/runs/'+load.RUN+'/hosts/'+load.HOST+'/'+name,'--only-show-errors'],capture_output=True,check=True)
print(json.dumps(report))
if report['status']!='passed':raise SystemExit(1)
PY
