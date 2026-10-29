#!/bin/bash
set -euo pipefail
umask 077
python3 - <<'PY'
import json,sys
sys.path.insert(0,'/opt/bower-lab')
import control
# Published detector fixture from docs/deployment/packs.md, not a random identifier.
values={'au.tfn':'123456782','fin.card':'4000000000000002','id.email':'synthetic.person@example.invalid','id.phone.au':'0491570006'}
corpus={'values':values,'positiveControl':'lab-host.example.invalid','synthetic':True}
control.write(control.ROOT/'seed-manifest.json',json.dumps(corpus))
control.store_secret('corpus',corpus)
print(json.dumps({'phase':'synthetic-corpus','status':'ready','detectors':list(values),'manifest':'lab-only'}))
PY
