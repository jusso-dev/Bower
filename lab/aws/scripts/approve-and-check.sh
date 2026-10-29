#!/bin/bash
set -euo pipefail
umask 077
python3 - <<'PY'
import json,sys,time,ssl,urllib.request,urllib.error
from pathlib import Path
sys.path.insert(0,'/opt/bower-lab')
import control
root=control.ROOT
manifest=json.loads((root/'manifest.json').read_text())
ids=[control.RUN+'-'+host.lower() for host in manifest['hosts'] if host!='Control']
statuses={}
for attempt in range(120):
    for collector in ids:
        try:
            record=control.api('/api/collectors/'+collector)
            if record['status']=='Pending':
                control.api('/api/approvals/'+collector+'/approve',{'reason':'Disposable AWS lab smoke validation'})
            statuses[collector]=record['status']
        except urllib.error.HTTPError as error:
            if error.code!=404: raise
            statuses[collector]='not-registered'
    if all(statuses.get(collector)=='Active' for collector in ids): break
    time.sleep(3)
context=ssl.create_default_context(cafile=str(root/'pki/ca.crt'))
negative={}
for label,path,headers in [('anonymous-admin','/api/collectors',{}),('invalid-assertion','/api/collectors',{'Authorization':'Bearer bwc1.invalid'}),('remote-dashboard','/',{})]:
    request=urllib.request.Request('https://'+manifest['hosts']['Control']['ip']+path,headers=headers)
    try:
        with urllib.request.urlopen(request,context=context,timeout=10) as response:
            negative[label]=response.status
    except urllib.error.HTTPError as error:
        negative[label]=error.code
passed=all(value=='Active' for value in statuses.values()) and negative=={'anonymous-admin':401,'invalid-assertion':401,'remote-dashboard':403}
report={'phase':'P0-fleet','status':'passed' if passed else 'failed','collectors':statuses,'negativeAuth':negative,'sentinel':'deferred','adminAuthentication':'isolated-development-loopback'}
(root/'P0-fleet.json').write_text(json.dumps(report,indent=2)+'\n')
control.run('aws','--region',control.REGION,'s3','cp',str(root/'P0-fleet.json'),'s3://'+control.BUCKET+'/runs/'+control.RUN+'/P0/fleet.json','--only-show-errors')
print(json.dumps(report))
if not passed: raise SystemExit(1)
PY
