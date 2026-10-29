#!/bin/bash
set -euo pipefail
umask 077
python3 - <<'PY'
import json,sys,subprocess
from pathlib import Path
sys.path.insert(0,'/opt/bower-lab')
import load
corpus=json.loads(load.aws('secretsmanager','get-secret-value','--secret-id','bower-lab/'+load.RUN+'/corpus')['SecretString'])
item=load.event(1,'replay',0,0,corpus)
first=load.send(item)[1];identical=load.send(item)[1]
payload=json.loads(item[1]);payload['eventOutcomeReason']='DifferentSyntheticReason'
conflicting=load.send((item[0],json.dumps(payload).encode(),False))[1]
report={'phase':'replay','host':load.HOST,'first':first,'identical':identical,'conflicting':conflicting,'status':'passed' if (first,identical,conflicting)==(202,200,409) else 'failed'}
root=Path('/opt/bower-lab/results')
(root/'replay.json').write_text(json.dumps(report))
(root/'replay.acks.json').write_text(json.dumps({'acknowledged':[item[0]] if first in (200,202) else [],'denied':[]}))
for name in ('replay.json','replay.acks.json'):
    subprocess.run(['aws','s3','cp',str(root/name),'s3://'+load.BUCKET+'/runs/'+load.RUN+'/hosts/'+load.HOST+'/'+name,'--only-show-errors'],capture_output=True,check=True)
print(json.dumps(report))
if report['status']!='passed': raise SystemExit(1)
PY
