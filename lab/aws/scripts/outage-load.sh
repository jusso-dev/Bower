#!/bin/bash
set -euo pipefail
python3 /opt/bower-lab/load.py --phase outage --count 500 --rate 50 --seconds 20
python3 - <<'PY'
import json,sqlite3,os,subprocess
from pathlib import Path
c=sqlite3.connect('file:/var/lib/bower/queue.db?mode=ro',uri=True)
s=dict(c.execute('SELECT state,count(*) FROM queue_events_v5 GROUP BY state'));c.close()
p=Path('/opt/bower-lab/results/outage-queue.json');p.write_text(json.dumps({'host':os.environ['BOWER_LAB_HOST'],'queueStates':s}))
subprocess.run(['aws','s3','cp',str(p),'s3://'+os.environ['BOWER_LAB_BUCKET']+'/runs/'+os.environ['BOWER_LAB_RUN']+'/hosts/'+os.environ['BOWER_LAB_HOST']+'/outage-queue.json','--only-show-errors'],capture_output=True,check=True)
print(p.read_text())
PY
