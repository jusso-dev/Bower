#!/bin/bash
set -euo pipefail
umask 077
python3 - <<'PY'
import json,secrets,sys
sys.path.insert(0,'/opt/bower-lab')
import control
weights=[1,4,3,7,5,8,6,9,10]
while True:
    digits=[secrets.randbelow(9)+1]+[secrets.randbelow(10) for _ in range(8)]
    if sum(value*weight for value,weight in zip(digits,weights))%11==0: break
values={'au.tfn':''.join(map(str,digits)),'fin.card':'4000000000000002','id.email':'synthetic.person@example.invalid','id.phone.au':'0491570006'}
corpus={'values':values,'positiveControl':'lab-host.example.invalid','synthetic':True}
control.write(control.ROOT/'seed-manifest.json',json.dumps(corpus))
control.store_secret('corpus',corpus)
print(json.dumps({'phase':'synthetic-corpus','status':'ready','detectors':list(values),'manifest':'lab-only'}))
PY
