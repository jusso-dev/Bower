#!/bin/bash
set -euo pipefail
umask 077
python3 - <<'PY'
import json,os,subprocess,time
from pathlib import Path
run=os.environ['BOWER_LAB_RUN'];expected={f'{run}-{host}-outage-{i}' for host in ('linux1','linux2') for i in range(1,501)}
started=time.monotonic();found={}
while time.monotonic()-started<120:
    for path in Path('/var/lib/bower/spool/ready').glob('*.jsonl'):
        for line in path.open():
            event=json.loads(line)
            if event['eventId'] in expected:found[event['eventId']]=path.stat().st_mtime
    if len(found)==len(expected):break
    time.sleep(2)
active=int(subprocess.run(['systemctl','show','bower','--property','ActiveEnterTimestampMonotonic','--value'],capture_output=True,text=True,check=True).stdout)/1e6
restart=time.time()-(time.monotonic()-active)
recovery=max(0,max(found.values())-restart) if found else None
report={'phase':'relay-outage','expected':len(expected),'landed':len(found),'recoverySeconds':recovery,'thresholdSeconds':120,'status':'passed' if len(found)==len(expected) and recovery<=120 else 'failed'}
p=Path('/opt/bower-lab/results/outage-recovery.json');p.write_text(json.dumps(report))
subprocess.run(['aws','s3','cp',str(p),'s3://'+os.environ['BOWER_LAB_BUCKET']+'/runs/'+run+'/hosts/Collector/outage-recovery.json','--only-show-errors'],check=True,capture_output=True)
print(json.dumps(report))
if report['status']!='passed':raise SystemExit(1)
PY
